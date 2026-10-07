import secrets

from venture128.modules.enc_dec import encrypt_block
from venture128.modules.padding import pkcs7_pad, pkcs7_unpad
from venture128.variables.constants import BLOCK_SIZE_BYTES


def ctr_encrypt(
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

    padded_data = pkcs7_pad(data, BLOCK_SIZE_BYTES)
    ciphertext = bytearray()
    counter = int.from_bytes(iv, "big")
    max_counter = (1 << (8 * BLOCK_SIZE_BYTES)) - 1

    for i in range(0, len(padded_data), BLOCK_SIZE_BYTES):
        if counter > max_counter:
            raise ValueError("CTR counter overflow, will wrap and reuse block.")

        counter_block = counter.to_bytes(BLOCK_SIZE_BYTES, "big")
        keystream = encrypt_block(counter_block, keys)
        chunk = padded_data[i : i + BLOCK_SIZE_BYTES]
        ciphertext.extend(a ^ b for a, b in zip(chunk, keystream))
        counter += 1

    return bytes(ciphertext), iv


def ctr_decrypt(
    data: bytes,
    keys,
    iv: bytes,
) -> bytes:
    if not iv or len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv) if iv else 0} bytes."
        )
    if not data or len(data) % BLOCK_SIZE_BYTES:
        raise ValueError(
            f"Ciphertext length must be a non-empty multiple of {BLOCK_SIZE_BYTES} bytes."
        )

    plaintext = bytearray()
    counter = int.from_bytes(iv, "big")
    max_counter = (1 << (8 * BLOCK_SIZE_BYTES)) - 1

    for i in range(0, len(data), BLOCK_SIZE_BYTES):
        if counter > max_counter:
            raise ValueError("CTR counter overflow, will wrap and reuse block.")

        counter_block = counter.to_bytes(BLOCK_SIZE_BYTES, "big")
        keystream = encrypt_block(counter_block, keys)
        chunk = data[i : i + BLOCK_SIZE_BYTES]
        plaintext.extend(a ^ b for a, b in zip(chunk, keystream))
        counter += 1

    return pkcs7_unpad(bytes(plaintext), BLOCK_SIZE_BYTES)