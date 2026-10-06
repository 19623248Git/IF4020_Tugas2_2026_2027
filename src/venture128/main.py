import argparse
import ast
import sys
from importlib.metadata import version
from pathlib import Path

from venture128.block_modes import cbc, cfb, ctr, ecb, ofb
from venture128.modules.iv import generate_iv, parse_iv
from venture128.modules.key_expand import generate_round_keys
from venture128.variables.constants import BLOCK_SIZE_BYTES, KEY_SIZE_BYTES

BLOCK_MODES = {1: "ecb", 2: "cbc", 3: "cfb", 4: "ofb", 5: "ctr"}

STDIN_ARG = "-"


def block_mode_type(value: str) -> str:
    v = value.strip().lower()
    if v.isdigit() and int(v) in BLOCK_MODES:
        return BLOCK_MODES[int(v)]
    if v in BLOCK_MODES.values():
        return v
    raise argparse.ArgumentTypeError(
        f"invalid block mode {value!r}, choose 1/ecb, 2/cbc, 3/cfb, 4/ofb or 5/ctr"
    )


DESCRIPTION = f"""\
Venture128 block cipher ({BLOCK_SIZE_BYTES * 8}-bit block, {KEY_SIZE_BYTES * 8}-bit key).

Encrypts or decrypts data with a {KEY_SIZE_BYTES}-byte key in ECB, CBC, CFB, OFB or CTR mode."""

EPILOG = f"""\
input formats:
  -f plain.txt                 any file, read as raw bytes
  -s "hello world"             UTF-8 text
  -hex "de ad be ef"           hex digits, whitespace and a leading 0x are ignored
  -b "01000001 01000010"       bits, whitespace is ignored, length must be a multiple of 8
  -Bd "222 173 190 239"        decimal byte values 0-255, space separated
  -Bl "b'\\xde\\xad\\xbe\\xef'"    Python bytes literal
  -raw                         raw binary from stdin
  -hex, -b, -Bd and -Bl with no value read their text from stdin instead

IV (CBC, CFB, OFB, CTR):
  without -iv, encryption generates a random {BLOCK_SIZE_BYTES}-byte IV and prepends it to the ciphertext
  decryption reads it back from the first {BLOCK_SIZE_BYTES} bytes 
  with -iv, the iv is not prepended, and must be given again to decrypt
    -iv hex 000102030405060708090a0b0c0d0e0f
    -iv file iv.bin
    -iv bits "00000000 00000001 ..."
    -iv bytes "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"

examples:
  venture128 --block-mode ecb -e -key "0123456789abcdef" -s "hello" -o cipher.bin
  venture128 --block-mode ecb -d -key "0123456789abcdef" -f cipher.bin -of raw
  echo "deadbeef" | venture128 --block-mode cbc -e -key-file key.txt -hex
  head -c 64 /dev/urandom | venture128 --block-mode 5 -e -key-hex 000102030405060708090a0b0c0d0e0f -raw
  venture128 --block-mode 2 -e -key "0123456789abcdef" -s "hi" -of raw \\
    | venture128 --block-mode 2 -d -key "0123456789abcdef" -raw -of raw"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="venture128",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    p.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {version('venture128')}"
    )

    # block mode and encrypt or decrypt mode
    g_op = p.add_argument_group("operation")
    g_op.add_argument(
        "--block-mode",
        type=block_mode_type,
        required=True,
        metavar="MODE",
        help="1/ecb, 2/cbc, 3/cfb, 4/ofb or 5/ctr",
    )
    p1 = g_op.add_mutually_exclusive_group(required=True)
    p1.add_argument(
        "-e",
        dest="enc_dec_mode",
        action="store_const",
        const="encrypt",
        help="encrypt the input",
    )
    p1.add_argument(
        "-d",
        dest="enc_dec_mode",
        action="store_const",
        const="decrypt",
        help="decrypt the input",
    )

    # key input
    g_key = p.add_argument_group("key (choose one)")
    p2 = g_key.add_mutually_exclusive_group(required=True)
    p2.add_argument(
        "-key", metavar='"STRING"', help=f"key as a {KEY_SIZE_BYTES}-character string"
    )
    p2.add_argument(
        "-key-file",
        metavar="PATH",
        help=f"read a {KEY_SIZE_BYTES}-byte key from a file (a trailing newline is ignored)",
    )
    p2.add_argument(
        "-key-hex", metavar="HEX", help=f"key as {KEY_SIZE_BYTES * 2} hex digits"
    )

    g_iv = p.add_argument_group("initialization vector")
    g_iv.add_argument(
        "-iv",
        nargs=2,
        metavar=("{file,hex,bits,bytes}", "VALUE"),
        help=f"{BLOCK_SIZE_BYTES}-byte IV for CBC/CFB/OFB/CTR, ignored by ECB (default: random, prepended to the ciphertext)",
    )

    # data input
    g_in = p.add_argument_group("input (choose one)")
    p3 = g_in.add_mutually_exclusive_group(required=True)
    p3.add_argument("-f", dest="file", metavar="PATH", help="read input from a file")
    p3.add_argument(
        "-s", dest="string", metavar='"STRING"', help="input as a quoted UTF-8 string"
    )
    p3.add_argument(
        "-hex",
        dest="hex",
        nargs="?",
        const=STDIN_ARG,
        metavar="HEX",
        help="input as hex digits",
    )
    p3.add_argument(
        "-b",
        dest="bits",
        nargs="?",
        const=STDIN_ARG,
        metavar="BITS",
        help="input as bits",
    )
    p3.add_argument(
        "-Bd",
        dest="byte_decimal",
        nargs="?",
        const=STDIN_ARG,
        metavar='"BYTES"',
        help="input as decimal byte values 0-255",
    )
    p3.add_argument(
        "-Bl",
        dest="byte_literal",
        nargs="?",
        const=STDIN_ARG,
        metavar='"LITERAL"',
        help="input as a Python bytes literal",
    )
    p3.add_argument(
        "-raw",
        dest="raw",
        action="store_true",
        help="read raw binary input from stdin",
    )

    g_out = p.add_argument_group("output")
    g_out.add_argument(
        "-o", dest="output", metavar="PATH", help="write output to a file instead of stdout"
    )
    g_out.add_argument(
        "-of",
        dest="out_format",
        choices=["raw", "hex", "bits"],
        help="output format (default: raw with -o, hex on stdout)",
    )
    return p


def parse_hex(text: str) -> bytes:
    digits = "".join(text.split())
    if digits[:2].lower() == "0x":
        digits = digits[2:]
    if len(digits) % 2:
        raise ValueError("invalid hex input, not even length")
    return bytes.fromhex(digits)


def parse_bits(text: str) -> bytes:
    clean_bits = "".join(text.split())
    if any(c not in "01" for c in clean_bits):
        raise ValueError("invalid bit input, only '0' and '1' allowed")
    if len(clean_bits) % 8 != 0:
        raise ValueError(
            f"invalid bit input, length must be a multiple of 8, got {len(clean_bits)}"
        )
    return bytes(int(clean_bits[i : i + 8], 2) for i in range(0, len(clean_bits), 8))


def parse_byte_literal(text: str) -> bytes:
    try:
        value = ast.literal_eval(text.strip())
    except SyntaxError as e:
        raise ValueError(f"invalid bytes literal: {e.msg}")
    except ValueError:
        raise ValueError("invalid bytes literal, only literals like b'\\x00' are allowed")
    if not isinstance(value, bytes):
        raise ValueError(
            f"expected a bytes literal like b'\\x00', got {type(value).__name__}"
        )
    return value


def read_key(args: argparse.Namespace) -> bytes:
    if args.key is not None:
        key = args.key.encode()
    elif args.key_hex is not None:
        key = parse_hex(args.key_hex)
    else:
        key = Path(args.key_file).read_bytes()
        if len(key) != KEY_SIZE_BYTES:
            key = key.rstrip(b"\r\n")
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"key must be exactly {KEY_SIZE_BYTES} bytes, got {len(key)}")
    return key


def read_stdin_text() -> str:
    if sys.stdin.isatty():
        print("reading from stdin, finish with Ctrl-D", file=sys.stderr)
    return sys.stdin.read()


def read_stdin_bytes() -> bytes:
    if sys.stdin.isatty():
        print("reading from stdin, finish with Ctrl-D", file=sys.stderr)
    return sys.stdin.buffer.read()


def read_input_data(args: argparse.Namespace) -> bytes:
    if args.file is not None:
        return Path(args.file).read_bytes()
    if args.string is not None:
        return args.string.encode()
    if args.raw:
        return read_stdin_bytes()

    if (
        args.hex == STDIN_ARG
        or args.bits == STDIN_ARG
        or args.byte_decimal == STDIN_ARG
        or args.byte_literal == STDIN_ARG
    ):
        raw_text = read_stdin_text().strip()
    else:
        raw_text = None

    if args.hex is not None:
        return parse_hex(raw_text if raw_text is not None else args.hex)
    if args.bits is not None:
        return parse_bits(raw_text if raw_text is not None else args.bits)
    if args.byte_decimal is not None:
        text = raw_text if raw_text is not None else args.byte_decimal
        return bytes(int(x) for x in text.split())
    if args.byte_literal is not None:
        return parse_byte_literal(
            raw_text if raw_text is not None else args.byte_literal
        )

    raise ValueError("No valid input data provided.")


def write_output(data: bytes, args: argparse.Namespace) -> None:
    fmt = args.out_format
    if fmt is None:
        fmt = "raw" if args.output else "hex"

    if fmt == "hex":
        formatted_str = data.hex()
    elif fmt == "bits":
        formatted_str = "".join(f"{b:08b}" for b in data)
    else:
        formatted_str = None

    if args.output:
        out_path = Path(args.output)
        if fmt == "raw":
            out_path.write_bytes(data)
        else:
            out_path.write_text(formatted_str + "\n")
    else:
        if fmt == "raw":
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(formatted_str + "\n")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        master_key = read_key(args)
        round_keys = generate_round_keys(master_key)
        input_data = read_input_data(args)
        mode = args.block_mode
        iv = None
        if mode in ("cbc", "cfb", "ofb", "ctr"):
            if args.iv:
                iv = parse_iv(args.iv[0], args.iv[1])
            elif args.enc_dec_mode == "encrypt":
                iv = generate_iv()
            else:
                if len(input_data) < BLOCK_SIZE_BYTES:
                    raise ValueError(
                        f"ciphertext is too short to contain a {BLOCK_SIZE_BYTES}-byte IV"
                    )
                iv = input_data[:BLOCK_SIZE_BYTES]
                input_data = input_data[BLOCK_SIZE_BYTES:]
        if mode == "ecb":
            if args.iv:
                print("venture128: warning: ignoring -iv flag for ECB", file=sys.stderr)
            res = (
                ecb.ecb_encrypt(input_data, round_keys)
                if args.enc_dec_mode == "encrypt"
                else ecb.ecb_decrypt(input_data, round_keys)
            )
        elif mode == "cbc":
            res = (
                cbc.cbc_encrypt(input_data, round_keys, iv)
                if args.enc_dec_mode == "encrypt"
                else cbc.cbc_decrypt(input_data, round_keys, iv)
            )
        elif mode == "cfb":
            res = (
                cfb.cfb_encrypt(input_data, round_keys, iv)
                if args.enc_dec_mode == "encrypt"
                else cfb.cfb_decrypt(input_data, round_keys, iv)
            )
        elif mode == "ofb":
            res = (
                ofb.ofb_encrypt(input_data, round_keys, iv)
                if args.enc_dec_mode == "encrypt"
                else ofb.ofb_decrypt(input_data, round_keys, iv)
            )
        elif mode == "ctr":
            res = (
                ctr.ctr_encrypt(input_data, round_keys, iv)
                if args.enc_dec_mode == "encrypt"
                else ctr.ctr_decrypt(input_data, round_keys, iv)
            )

        # Handle tuple return (data, iv) from encrypt modes
        if isinstance(res, tuple):
            output_data, used_iv = res
            if not args.iv and args.enc_dec_mode == "encrypt":
                output_data = used_iv + output_data
        else:
            output_data = res

        write_output(output_data, args)

    except (ValueError, OSError) as e:
        parser.exit(1, f"venture128: error: {e}\n")


if __name__ == "__main__":
    main()
