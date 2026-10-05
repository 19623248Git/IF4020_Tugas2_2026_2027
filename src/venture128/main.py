import argparse

BLOCK_MODES = {
    1: "ecb", 
    2: "cbc", 
    3: "cfb", 
    4: "ofb", 
    5: "ctr"
}

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
    return p

def handle_args(args):
    return 0

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

if __name__ == "__main__":
    main()
