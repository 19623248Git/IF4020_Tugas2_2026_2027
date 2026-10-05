import secrets

from venture128.modules.enc_dec import encrypt_block
from venture128.variables.constants import BLOCK_SIZE_BYTES


def _parse_segment_size(segment_size: int) -> int:
    if 1 <= segment_size <= BLOCK_SIZE_BYTES:
        return segment_size
    if segment_size % 8 == 0 and 8 <= segment_size <= BLOCK_SIZE_BYTES * 8:
        return segment_size // 8
    raise ValueError(f"Invalid segment_size {segment_size}.")


def cfb_encrypt(
    plaintext: bytes,
    keys,
    iv: bytes | None = None,
    segment_size: int = 128,
) -> tuple[bytes, bytes]:
    seg_bytes = _parse_segment_size(segment_size)

    if iv is None:
        iv = secrets.token_bytes(BLOCK_SIZE_BYTES)
    elif len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv)} bytes."
        )

    ciphertext = bytearray()
    shift_register = iv

    for i in range(0, len(plaintext), seg_bytes):
        plain_chunk = plaintext[i : i + seg_bytes]
        output_block = encrypt_block(shift_register, keys)
        cipher_chunk = bytes(
            p ^ o for p, o in zip(plain_chunk, output_block[: len(plain_chunk)])
        )
        ciphertext.extend(cipher_chunk)
        shift_register = shift_register[len(cipher_chunk) :] + cipher_chunk

    return bytes(ciphertext), iv


def cfb_decrypt(
    ciphertext: bytes,
    keys,
    iv: bytes,
    segment_size: int = 128,
) -> bytes:
    seg_bytes = _parse_segment_size(segment_size)

    if not iv or len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(
            f"IV must be exactly {BLOCK_SIZE_BYTES} bytes, got {len(iv) if iv else 0} bytes."
        )

    plaintext = bytearray()
    shift_register = iv

    for i in range(0, len(ciphertext), seg_bytes):
        cipher_chunk = ciphertext[i : i + seg_bytes]
        output_block = encrypt_block(shift_register, keys)
        plain_chunk = bytes(
            c ^ o for c, o in zip(cipher_chunk, output_block[: len(cipher_chunk)])
        )
        plaintext.extend(plain_chunk)
        shift_register = shift_register[len(cipher_chunk) :] + cipher_chunk

    return bytes(plaintext)
