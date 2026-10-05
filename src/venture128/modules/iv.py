import os
from pathlib import Path

from venture128.variables.constants import BLOCK_SIZE_BYTES


def generate_iv(length: int = BLOCK_SIZE_BYTES) -> bytes:
    return os.urandom(length)


def parse_iv(iv_type: str, iv_value: str) -> bytes:
    iv_type = iv_type.lower()

    if iv_type == "file":
        iv_bytes = Path(iv_value).read_bytes()
        if len(iv_bytes) != BLOCK_SIZE_BYTES:
            iv_bytes = iv_bytes.rstrip(b"\r\n")

    elif iv_type == "hex":
        clean_hex = "".join(iv_value.split())
        if clean_hex.startswith(("0x", "0X")):
            clean_hex = clean_hex[2:]
        if len(clean_hex) % 2 != 0:
            raise ValueError("Hex IV string must have an even length.")
        iv_bytes = bytes.fromhex(clean_hex)

    elif iv_type == "bits":
        clean_bits = "".join(iv_value.split())
        if any(c not in "01" for c in clean_bits):
            raise ValueError("Bit IV string must only contain '0' and '1'.")
        if len(clean_bits) % 8 != 0:
            raise ValueError("Bit IV length must be a multiple of 8.")
        iv_bytes = bytes(
            int(clean_bits[i : i + 8], 2) for i in range(0, len(clean_bits), 8)
        )

    elif iv_type == "bytes":
        parts = iv_value.split()
        iv_bytes = bytes(int(p) for p in parts)

    else:
        raise ValueError(
            f"Unsupported IV type: {iv_type}. Supported: file, hex, bits, bytes"
        )

    if len(iv_bytes) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes ({BLOCK_SIZE_BYTES * 8} bits), "
            f"got {len(iv_bytes)} bytes."
        )

    return iv_bytes
