import secrets

from venture128.modules.enc_dec import encrypt_block
from venture128.variables.constants import BLOCK_SIZE_BYTES


def ofb_encrypt(
    data: bytes,
    keys,
    iv: bytes | None = None,
) -> tuple[bytes, bytes]:
    if iv is None:
        iv = secrets.token_bytes(BLOCK_SIZE_BYTES)
    elif len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv)} bytes."
        )

    ciphertext = bytearray()
    feedback = iv

    for i in range(0, len(data), BLOCK_SIZE_BYTES):
        feedback = encrypt_block(feedback, keys)
        chunk = data[i : i + BLOCK_SIZE_BYTES]
        ciphertext.extend(a ^ b for a, b in zip(chunk, feedback))

    return bytes(ciphertext), iv


def ofb_decrypt(
    data: bytes,
    keys,
    iv: bytes,
) -> bytes:
    if not iv or len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv) if iv else 0} bytes."
        )

    plaintext = bytearray()
    feedback = iv

    for i in range(0, len(data), BLOCK_SIZE_BYTES):
        feedback = encrypt_block(feedback, keys)
        chunk = data[i : i + BLOCK_SIZE_BYTES]
        plaintext.extend(a ^ b for a, b in zip(chunk, feedback))

    return bytes(plaintext)