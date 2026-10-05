import secrets

from venture128.modules.enc_dec import decrypt_block, encrypt_block
from venture128.modules.padding import pkcs7_pad, pkcs7_unpad
from venture128.variables.constants import BLOCK_SIZE_BYTES


def cbc_encrypt(
    plaintext: bytes,
    keys,
    iv: bytes | None = None,
) -> tuple[bytes, bytes]:
    if iv is None:
        iv = secrets.token_bytes(BLOCK_SIZE_BYTES)
    elif len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv)} bytes."
        )

    padded = pkcs7_pad(plaintext, BLOCK_SIZE_BYTES)
    ciphertext = bytearray()
    previous_block = iv

    for i in range(0, len(padded), BLOCK_SIZE_BYTES):
        block = padded[i : i + BLOCK_SIZE_BYTES]
        xored = bytes(p ^ c for p, c in zip(block, previous_block))
        encrypted_block = encrypt_block(xored, keys)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block

    return bytes(ciphertext), iv


def cbc_decrypt(
    ciphertext: bytes,
    keys,
    iv: bytes,
) -> bytes:
    if not ciphertext or len(ciphertext) % BLOCK_SIZE_BYTES != 0:
        raise ValueError(
            f"Ciphertext length must be a non-empty multiple of {BLOCK_SIZE_BYTES} bytes."
        )
    if not iv or len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv) if iv else 0} bytes."
        )

    decrypted_padded = bytearray()
    previous_block = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE_BYTES):
        block = ciphertext[i : i + BLOCK_SIZE_BYTES]
        decrypted_block = decrypt_block(block, keys)
        plaintext_block = bytes(d ^ p for d, p in zip(decrypted_block, previous_block))
        decrypted_padded.extend(plaintext_block)
        previous_block = block

    return pkcs7_unpad(bytes(decrypted_padded), BLOCK_SIZE_BYTES)
