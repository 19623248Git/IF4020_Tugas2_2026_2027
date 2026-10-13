import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from venture128.block_modes import cbc, cfb, ctr, ecb, ofb
from venture128.modules.key_expand import generate_round_keys

KEY = b"0123456789abcdef"
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]


def run_encrypt(mode: str, data: bytes, round_keys: list, iv: bytes) -> bytes:
    if mode == "ecb":
        res = ecb.ecb_encrypt(data, round_keys)
    elif mode == "cbc":
        res = cbc.cbc_encrypt(data, round_keys, iv)
    elif mode == "cfb":
        res = cfb.cfb_encrypt(data, round_keys, iv)
    elif mode == "ofb":
        res = ofb.ofb_encrypt(data, round_keys, iv)
    elif mode == "ctr":
        res = ctr.ctr_encrypt(data, round_keys, iv)
    return res[0] if isinstance(res, tuple) else res


def run_decrypt(mode: str, data: bytes, round_keys: list, iv: bytes) -> bytes:
    if mode == "ecb":
        res = ecb.ecb_decrypt(data, round_keys)
    elif mode == "cbc":
        res = cbc.cbc_decrypt(data, round_keys, iv)
    elif mode == "cfb":
        res = cfb.cfb_decrypt(data, round_keys, iv)
    elif mode == "ofb":
        res = ofb.ofb_decrypt(data, round_keys, iv)
    elif mode == "ctr":
        res = ctr.ctr_decrypt(data, round_keys, iv)
    return res[0] if isinstance(res, tuple) else res


def test_sha256_integrity(round_keys: list) -> None:
    plaintext = b"Testing ventrure 128 data integrity."
    pt_hash = hashlib.sha256(plaintext).hexdigest()
    print(f"Original Plaintext SHA-256 : {pt_hash}\n")

    for mode in MODES:
        ct = run_encrypt(mode, plaintext, round_keys, IV)
        dec = run_decrypt(mode, ct, round_keys, IV)
        dec_hash = hashlib.sha256(dec).hexdigest()
        is_match = pt_hash == dec_hash
        status = "MATCH" if is_match else "FAILED"
        print(f"[{mode.upper():<3}] Decrypted SHA-256: {dec_hash} | {status}")


def main():
    round_keys = generate_round_keys(KEY)
    test_sha256_integrity(round_keys)


if __name__ == "__main__":
    main()
