"""Entropy test for Venture128 in ECB, CBC, CFB, OFB, and CTR modes.

Measures byte-level Shannon entropy:
    H(X) = - sum_{i=0}^{255} P(x_i) * log2(P(x_i))

Usage:
    python ./tests/test_entropy.py
    python ./tests/test_entropy.py --input tests/input/plaintext_long.txt
    python ./tests/test_entropy.py --modes ecb cbc ctr --verbose
    python ./tests/test_entropy.py --synthetic --size 4096
"""

import argparse
import math
import sys
from collections import Counter
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
MAX_BYTE_ENTROPY = 8.0  # bits per byte


# ---------------------------------------------------------------- metrics


def shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def max_possible_entropy(data_len: int) -> float:

    if data_len <= 1:
        return 0.0
    return min(MAX_BYTE_ENTROPY, math.log2(data_len))


def encrypt_mode(mode: str, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts plaintext with specified mode and fixed IV. Returns ciphertext."""
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


# ---------------------------------------------------------------- helpers


def load_default_inputs(input_arg: str | None) -> list[tuple[str, bytes]]:
    if input_arg:
        p = Path(input_arg)
        if not p.exists():
            p = REPO_ROOT / input_arg
        if not p.is_file():
            raise ValueError(f"input file not found: {input_arg}")
        return [(p.name, p.read_bytes())]

    files = sorted(DEFAULT_INPUT_DIR.glob("plaintext_*"))
    if not files:
        raise ValueError(f"no plaintext_* files found in {DEFAULT_INPUT_DIR}")
    return [(f.name, f.read_bytes()) for f in files]


def generate_synthetic_inputs(size: int = 1024) -> list[tuple[str, bytes]]:
    """Generates synthetic test patterns to demonstrate entropy transformation."""
    # Ensure size is at least 16 bytes
    size = max(16, size)

    # 1. Zero bytes (entropy = 0)
    zeros = b"\x00" * size

    # 2. Repeated ASCII text (low entropy)
    pattern = b"Venture128-IF4020-Cryptography-Test-"
    repeated = (pattern * ((size // len(pattern)) + 1))[:size]

    # 3. Counter sequence 0x00..0xFF repeating
    counter = bytes(i % 256 for i in range(size))

    # 4. English natural text
    lorem = (
        b"In cryptography, a block cipher is a deterministic algorithm operating on fixed-length "
        b"groups of bits, termed a block. Symmetric-key ciphers use the same cryptographic keys for "
        b"both the encryption of plaintext and the decryption of ciphertext. Type-2 generalized "
        b"Feistel networks partition the block into multiple sub-blocks to achieve diffusion."
    )
    english = (lorem * ((size // len(lorem)) + 1))[:size]

    return [
        (f"synthetic_all_zeros_{size}B", zeros),
        (f"synthetic_repeated_ascii_{size}B", repeated),
        (f"synthetic_counter_0to255_{size}B", counter),
        (f"synthetic_english_text_{size}B", english),
    ]


# ---------------------------------------------------------------- CLI & Runner


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Venture128 Byte Entropy Test (ECB, CBC, CFB, OFB, CTR)."
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
        help="subset of modes to test (default: all)",
    )
    ap.add_argument(
        "--synthetic",
        action="store_true",
        help="run entropy tests on synthetic patterns (all zeros, repeating text, etc.)",
    )
    ap.add_argument(
        "--size",
        type=int,
        default=1024,
        help="byte size for synthetic input patterns (default: 1024 bytes)",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="display byte frequency histogram and chi-square statistics",
    )
    return ap.parse_args()


def print_histogram(data: bytes, title: str, top_n: int = 10) -> None:
    """Displays top most frequent bytes."""
    counts = Counter(data).most_common(top_n)
    n = len(data)
    print(f"    [Top {top_n} Byte Distribution for {title}]:")
    for b_val, count in counts:
        pct = (count / n) * 100.0
        bar = "#" * int(pct // 2)
        print(f"      0x{b_val:02x} ({b_val:>3}): {count:>5} ({pct:>5.1f}%) | {bar}")


def run_entropy_analysis(
    inputs: list[tuple[str, bytes]],
    key: bytes,
    iv: bytes,
    modes: list[str],
    verbose: bool = False,
) -> list[dict]:
    results: list[dict] = []

    for name, plaintext in inputs:
        n_plain = len(plaintext)
        h_plain = shannon_entropy(plaintext)
        max_possible_plain = max_possible_entropy(n_plain)

        print(
            "================================================================================"
        )
        print(f"Input: {name} ({n_plain} bytes)")
        print(
            f"Plaintext Entropy : {h_plain:.4f} / 8.0000 bits/byte "
            f"({(h_plain / MAX_BYTE_ENTROPY) * 100.0:.2f}% of max 8.0, "
            f"sample upper bound = {max_possible_plain:.4f})"
        )
        if verbose:
            print_histogram(plaintext, "Plaintext")

        print(
            "--------------------------------------------------------------------------------"
        )
        print(
            f"{'Mode':<6}{'Plain(B)':>9}{'Cipher(B)':>10}{'H(Plain)':>10}"
            f"{'H(Cipher)':>11}{'% of Max':>10}{'Delta H':>9}{'Status':>11}"
        )
        print(
            "--------------------------------------------------------------------------------"
        )

        for mode in modes:
            ciphertext = encrypt_mode(mode, plaintext, key, iv)
            n_cipher = len(ciphertext)
            h_cipher = shannon_entropy(ciphertext)
            max_possible_cipher = max_possible_entropy(n_cipher)
            pct_max = (h_cipher / MAX_BYTE_ENTROPY) * 100.0
            delta_h = h_cipher - h_plain

            # Evaluation status:
            # For adequate size (>= 256 bytes), entropy is expected to be very high (> 7.5 bits/byte).
            # For small files, it should be close to sample upper bound.
            if h_cipher >= 7.8:
                status = "EXCELLENT"
            elif h_cipher >= 7.0 or (h_cipher / max_possible_cipher >= 0.95):
                status = "GOOD"
            else:
                status = "FAIR"

            row = {
                "input_name": name,
                "mode": mode.upper(),
                "plain_len": n_plain,
                "cipher_len": n_cipher,
                "h_plain": round(h_plain, 4),
                "h_cipher": round(h_cipher, 4),
                "pct_of_max": round(pct_max, 2),
                "delta_h": round(delta_h, 4),
                "sample_max": round(max_possible_cipher, 4),
                "status": status,
            }
            results.append(row)

            print(
                f"{mode.upper():<6}{n_plain:>9}{n_cipher:>10}{h_plain:>10.4f}"
                f"{h_cipher:>11.4f}{pct_max:>9.2f}%{delta_h:>+9.4f}{status:>11}"
            )

            if verbose:
                print_histogram(ciphertext, f"{mode.upper()} Ciphertext", top_n=5)

        print()

    return results


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

    if args.synthetic:
        inputs = generate_synthetic_inputs(args.size)
    else:
        try:
            inputs = load_default_inputs(args.input)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    print(
        "================================================================================"
    )
    print(
        "                      VENTURE128 CIPHERTEXT ENTROPY TEST                        "
    )
    print(
        "================================================================================"
    )
    print(f"Key        : {key.hex()} ({key!r})")
    print(f"IV (fixed) : {iv.hex()}")
    print(f"Modes      : {', '.join(m.upper() for m in args.modes)}")
    print(f"Max Entropy: {MAX_BYTE_ENTROPY:.1f} bits/byte (256 uniform byte symbols)\n")

    run_entropy_analysis(
        inputs=inputs,
        key=key,
        iv=iv,
        modes=args.modes,
        verbose=args.verbose,
    )

    print("Analisis Entropi Selesai.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
