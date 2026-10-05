import argparse
from venture128.variables.constants import KEY_SIZE_BYTES, BLOCK_SIZE_BYTES
from venture128.modules.key_expand import generate_round_keys
from pathlib import Path

BLOCK_MODES = {
    1: "ecb", 
    2: "cbc", 
    3: "cfb", 
    4: "ofb", 
    5: "ctr"
}

STDIN_ARG = "-"

def block_mode_type(value: str) -> str:
    v = value.strip().lower()
    if v.isdigit() and int(v) in BLOCK_MODES:
        return BLOCK_MODES[int(v)]
    if v in BLOCK_MODES.values():
        return v
    raise argparse.ArgumentTypeError(f"invalid block mode {value!r}, choose as follows: \n{BLOCK_MODES}")


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument(
        '--block-mode',
        type=block_mode_type,
        required=True,
        metavar=BLOCK_MODES
    )

    # encrypt or decrypt mode
    p1=p.add_mutually_exclusive_group(required=True)
    p1.add_argument(
        "-e",
        dest="enc_dec_mode",
        action="store_const",
        const="encrypt",
        help="encryption mode"
    )
    p1.add_argument(
        "-d",
        dest="enc_dec_mode",
        action="store_const",
        const="decrypt",
        help="decryption mode"
    )

    # key input
    p2 = p.add_mutually_exclusive_group(required=True)
    p2.add_argument(
        "-key", 
        metavar="STRING", 
        help=f"key as {KEY_SIZE_BYTES}-character string"
    )
    p2.add_argument(
        "-key-file", 
        metavar="PATH", 
        help=f"read file with {KEY_SIZE_BYTES}-byte key"
    )
    p2.add_argument(
        "-key-hex", 
        metavar="HEX", 
        help=f"key as {KEY_SIZE_BYTES * 2} hex"
    )

    p.add_argument(
        "-iv", 
        nargs=2, 
        metavar=("{file,hex,bits,bytes}", "VALUE"),
        help=f"{BLOCK_SIZE_BYTES}-byte IV for CBC/CFB/OFB/CTR (if not included, then random generated iv prepended to ciphertext)",
    )

    # data input
    p3 = p.add_mutually_exclusive_group(required=True)
    p3.add_argument(
        "-f", 
        dest="file", 
        metavar="PATH", 
        help="read input from a file"
    )
    p3.add_argument(
        "-s", 
        dest="string", 
        metavar='"STRING"', 
        help="input as a quoted string"
    )
    p3.add_argument(
        "-hex", 
        dest="hex", 
        nargs="?", 
        const=STDIN_ARG, 
        metavar="HEX", 
        help="input as hex"
    )
    p3.add_argument(
        "-b", 
        dest="bits", 
        nargs="?", 
        const=STDIN_ARG, 
        metavar="BITS", 
        help="input as bits"
    )
    p3.add_argument(
        "-Bd",
        dest="byte_decimal",
        nargs="?",
        const=STDIN_ARG,
        metavar='"BYTES"',
        help='input as decimal byte values 0-255, e.g. "222 173 190 239"'
    )
    p3.add_argument(
        "-Bl",
        dest="byte_literal",
        nargs="?",
        const=STDIN_ARG,
        metavar='"LITERAL"',
        help="input as a Python bytes literal, e.g. \"b'\\xde\\xad\\xbe\\xef'\""
    )
    p3.add_argument(
        "-raw",
        dest="raw",
        action="store_true",
        help="read raw binary input from stdin, e.g. head -c 64 /dev/urandom | venture128 ... -raw"
    )
    p.add_argument(
        "-o", 
        dest="output", 
        metavar="PATH", 
        help="write output to a file"
    )
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

def handle_args(args):
    return 0

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        key = generate_round_keys(read_key(args))
        
    except ValueError as e:
        parser.exit(1, f"venture128: error: {e}\n")
        

if __name__ == "__main__":
    main()
