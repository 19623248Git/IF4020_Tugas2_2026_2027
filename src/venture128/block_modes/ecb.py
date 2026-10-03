from venture128.modules.padding import *
from venture128.modules.enc_dec import encrypt_block, decrypt_block
from venture128.variables.constants import BLOCK_SIZE_BYTES

def ecb_encrypt(data: bytes, keys) -> bytes:
    data = pkcs7_pad(data)
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE_BYTES):
        out += encrypt_block(data[i:i + BLOCK_SIZE_BYTES], keys)
    return bytes(out)


def ecb_decrypt(data: bytes, keys) -> bytes:
    if not data or len(data) % BLOCK_SIZE_BYTES:
        raise ValueError(f"Ciphertext length is not multiple of {BLOCK_SIZE_BYTES} bytes.")
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE_BYTES):
        out += decrypt_block(data[i:i + BLOCK_SIZE_BYTES], keys)
    return pkcs7_unpad(bytes(out))