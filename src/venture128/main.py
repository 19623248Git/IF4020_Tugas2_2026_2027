import argparse
import sys
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
        f"invalid block mode {value!r}, choose as follows: \n{BLOCK_MODES}"
    )


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--block-mode", type=block_mode_type, required=True, metavar=BLOCK_MODES
    )

    # encrypt or decrypt mode
    p1 = p.add_mutually_exclusive_group(required=True)
    p1.add_argument(
        "-e",
        dest="enc_dec_mode",
        action="store_const",
        const="encrypt",
        help="encryption mode",
    )
    p1.add_argument(
        "-d",
        dest="enc_dec_mode",
        action="store_const",
        const="decrypt",
        help="decryption mode",
    )

    # key input
    p2 = p.add_mutually_exclusive_group(required=True)
    p2.add_argument(
        "-key", metavar="STRING", help=f"key as {KEY_SIZE_BYTES}-character string"
    )
    p2.add_argument(
        "-key-file", metavar="PATH", help=f"read file with {KEY_SIZE_BYTES}-byte key"
    )
    p2.add_argument("-key-hex", metavar="HEX", help=f"key as {KEY_SIZE_BYTES * 2} hex")

    p.add_argument(
        "-iv",
        nargs=2,
        metavar=("{file,hex,bits,bytes}", "VALUE"),
        help=f"{BLOCK_SIZE_BYTES}-byte IV for CBC/CFB/OFB/CTR (if not included, then random generated iv prepended to ciphertext)",
    )

    # data input
    p3 = p.add_mutually_exclusive_group(required=True)
    p3.add_argument("-f", dest="file", metavar="PATH", help="read input from a file")
    p3.add_argument(
        "-s", dest="string", metavar='"STRING"', help="input as a quoted string"
    )
    p3.add_argument(
        "-hex",
        dest="hex",
        nargs="?",
        const=STDIN_ARG,
        metavar="HEX",
        help="input as hex",
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
        help='input as decimal byte values 0-255, e.g. "222 173 190 239"',
    )
    p3.add_argument(
        "-Bl",
        dest="byte_literal",
        nargs="?",
        const=STDIN_ARG,
        metavar='"LITERAL"',
        help="input as a Python bytes literal, e.g. \"b'\\xde\\xad\\xbe\\xef'\"",
    )
    p3.add_argument(
        "-raw",
        dest="raw",
        action="store_true",
        help="read raw binary input from stdin, e.g. head -c 64 /dev/urandom | venture128 ... -raw",
    )
    p.add_argument("-o", dest="output", metavar="PATH", help="write output to a file")
    p.add_argument(
        "-of",
        dest="out_format",
        choices=["raw", "hex", "bits"],
        help="output format (if not included, then raw with -o or hex on stdout)",
    )
    return p


def parse_hex(text: str) -> bytes:
    digits = "".join(text.split())
    if digits[:2].lower() == "0x":
        digits = digits[2:]
    if len(digits) % 2:
        raise ValueError("invalid hex input, not even length")
    return bytes.fromhex(digits)


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


def read_input_data(args: argparse.Namespace) -> bytes:
    """Ingests input data from whichever CLI option was passed."""
    if args.file:
        return Path(args.file).read_bytes()
    if args.string is not None:
        return args.string.encode()
    if args.raw:
        return sys.stdin.buffer.read()

    # Read text for formatted stdin inputs
    if (
        args.hex == STDIN_ARG
        or args.bits == STDIN_ARG
        or args.byte_decimal == STDIN_ARG
        or args.byte_literal == STDIN_ARG
    ):
        raw_text = sys.stdin.read().strip()
    else:
        raw_text = None

    if args.hex is not None:
        return parse_hex(raw_text if raw_text is not None else args.hex)
    if args.bits is not None:
        text = raw_text if raw_text is not None else args.bits
        clean_bits = "".join(text.split())
        return bytes(
            int(clean_bits[i : i + 8], 2) for i in range(0, len(clean_bits), 8)
        )
    if args.byte_decimal is not None:
        text = raw_text if raw_text is not None else args.byte_decimal
        return bytes(int(x) for x in text.split())
    if args.byte_literal is not None:
        text = raw_text if raw_text is not None else args.byte_literal
        return eval(text)  # Expects standard byte literal string like b'\x00'

    raise ValueError("No valid input data provided.")


def write_output(data: bytes, args: argparse.Namespace) -> None:
    """Formats and writes output bytes to stdout or output file."""
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
        # 1. Load and expand key
        master_key = read_key(args)
        round_keys = generate_round_keys(master_key)

        # 2. Read input payload
        input_data = read_input_data(args)

        # 3. Handle IV if required by mode
        mode = args.block_mode
        iv = None
        if mode in ("cbc", "cfb", "ofb", "ctr"):
            if args.iv:
                iv = parse_iv(args.iv[0], args.iv[1])
            elif args.enc_dec_mode == "encrypt":
                iv = generate_iv()
            else:
                raise ValueError(
                    f"IV is required for decryption in {mode.upper()} mode."
                )

        # 4. Dispatch cipher operations
        if mode == "ecb":
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
            # Prepend IV to ciphertext if generated automatically without explicit output destination flag
            if not args.iv and args.enc_dec_mode == "encrypt":
                output_data = used_iv + output_data
        else:
            output_data = res

        # 5. Output results
        write_output(output_data, args)

    except Exception as e:
        parser.exit(1, f"venture128: error: {e}\n")


if __name__ == "__main__":
    main()
