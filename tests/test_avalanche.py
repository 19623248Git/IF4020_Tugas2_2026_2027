import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from venture128.block_modes import cbc, cfb, ctr, ecb, ofb
from venture128.modules.key_expand import generate_round_keys
from venture128.variables.constants import BLOCK_SIZE_BYTES

MODES = ("ecb", "cbc", "cfb", "ofb", "ctr")
DEFAULT_INPUT_DIR = Path(__file__).resolve().parent / "input"


# ---------------------------------------------------------------- helpers


def flip_bit(data: bytes, bit_index: int) -> bytes:
    total = len(data) * 8
    if not 0 <= bit_index < total:
        raise ValueError(f"bit_index {bit_index} out of range for {len(data)} bytes")
    byte_idx, bit_in_byte = divmod(bit_index, 8)
    mask = 0x80 >> bit_in_byte  # MSB-first ordering
    buf = bytearray(data)
    buf[byte_idx] ^= mask
    return bytes(buf)


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)} bytes")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def avalanche_pct(c1: bytes, c2: bytes) -> float:
    return 100.0 * hamming_distance(c1, c2) / (len(c1) * 8)


def encrypt_mode(mode: str, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys = generate_round_keys(key)
    if mode == "ecb":
        return ecb.ecb_encrypt(plaintext, round_keys)
    if mode == "cbc":
        ct, _ = cbc.cbc_encrypt(plaintext, round_keys, iv)
        return ct
    if mode == "cfb":
        ct, _ = cfb.cfb_encrypt(plaintext, round_keys, iv, segment_size=128)
        return ct
    if mode == "ofb":
        ct, _ = ofb.ofb_encrypt(plaintext, round_keys, iv)
        return ct
    if mode == "ctr":
        ct, _ = ctr.ctr_encrypt(plaintext, round_keys, iv)
        return ct
    raise ValueError(f"unknown mode {mode!r}")


def select_positions(nbytes: int, max_trials: int) -> list[int]:
    total = nbytes * 8
    if total <= max_trials:
        return list(range(total))
    step = total / max_trials
    return sorted({int(i * step) for i in range(max_trials)})


def run_avalanche(
    mode: str,
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    target: str,
    positions: list[int],
) -> list[float]:
    base_ct = encrypt_mode(mode, plaintext, key, iv)
    scores: list[float] = []
    for pos in positions:
        if target == "plaintext":
            ct = encrypt_mode(mode, flip_bit(plaintext, pos), key, iv)
        elif target == "key":
            ct = encrypt_mode(mode, plaintext, flip_bit(key, pos), iv)
        else:
            raise ValueError("target must be 'plaintext' or 'key'")
        scores.append(avalanche_pct(base_ct, ct))
    return scores


def summarize(scores: list[float]) -> tuple[float, float, float]:
    return sum(scores) / len(scores), min(scores), max(scores)


# ---------------------------------------------------------------- main


def load_default_inputs(input_arg: str | None) -> list[Path]:
    if input_arg:
        p = Path(input_arg)
        if not p.exists():
            p = REPO_ROOT / input_arg
        if not p.is_file():
            raise ValueError(f"input file not found: {input_arg}")
        return [p]
    files = sorted(DEFAULT_INPUT_DIR.glob("plaintext_*"))
    if not files:
        raise ValueError(f"no plaintext_* files found in {DEFAULT_INPUT_DIR}")
    return files


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Venture128 avalanche test (ECB..CTR), plaintext-flip and key-flip."
    )
    ap.add_argument(
        "--input",
        default=None,
        help="single plaintext file (default: all test/input/plaintext_*)",
    )
    ap.add_argument(
        "--key-file",
        default=str(DEFAULT_INPUT_DIR / "key_default.txt"),
        help="16-byte key file",
    )
    ap.add_argument(
        "--iv-hex-file",
        default=str(DEFAULT_INPUT_DIR / "iv_default.hex"),
        help="file holding 32 hex digits of IV",
    )
    ap.add_argument(
        "--modes",
        nargs="+",
        default=list(MODES),
        choices=list(MODES),
        help="subset of modes to test",
    )
    ap.add_argument(
        "--trials",
        type=int,
        default=128,
        help="max bit-flip trials per test (default 128; "
        "use e.g. 16 for a quick smoke test)",
    )
    ap.add_argument(
        "--verbose", action="store_true", help="print per-bit-position avalanche %%"
    )
    ap.add_argument(
        "--output", default=None, help="optional CSV path for the summary table"
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    key = Path(args.key_file).read_bytes()
    if len(key) != 16:
        key = key.rstrip(b"\r\n")
    if len(key) != 16:
        print(
            f"error: key must be 16 bytes, got {len(key)} from {args.key_file}",
            file=sys.stderr,
        )
        return 1
    iv = bytes.fromhex(Path(args.iv_hex_file).read_text().strip())
    if len(iv) != BLOCK_SIZE_BYTES:
        print(
            f"error: IV must be {BLOCK_SIZE_BYTES} bytes, got {len(iv)}",
            file=sys.stderr,
        )
        return 1

    try:
        input_files = load_default_inputs(args.input)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"key        : {key.hex()} ({key!r})")
    print(f"IV         : {iv.hex()}")

    rows: list[dict] = []
    for f in input_files:
        plaintext = f.read_bytes()
        print("======================================================================")
        print(f"{f.name} ({len(plaintext)} bytes)")
        print(
            f"{'mode':<6}{'test':<12}{'trials':>7}"
            f"{'avg%':>9}{'min%':>9}{'max%':>9}{'ct_len':>9}"
        )
        for mode in args.modes:
            base_ct = encrypt_mode(mode, plaintext, key, iv)
            for target in ("plaintext", "key"):
                nbytes = len(plaintext) if target == "plaintext" else len(key)
                positions = select_positions(nbytes, args.trials)
                scores = run_avalanche(mode, plaintext, key, iv, target, positions)
                avg, mn, mx = summarize(scores)
                print(
                    f"{mode:<6}{target:<12}{len(positions):>7}"
                    f"{avg:>9.2f}{mn:>9.2f}{mx:>9.2f}{len(base_ct):>9}"
                )
                rows.append(
                    {
                        "file": f.name,
                        "mode": mode,
                        "test": target,
                        "trials": len(positions),
                        "avg_pct": round(avg, 2),
                        "min_pct": round(mn, 2),
                        "max_pct": round(mx, 2),
                        "ct_len": len(base_ct),
                    }
                )
                if args.verbose:
                    for pos, s in zip(positions, scores):
                        print(f"    bit {pos:>4}: {s:5.2f}%")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
