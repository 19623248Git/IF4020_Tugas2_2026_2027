from venture128.modules.padding import *
from venture128.modules.enc_dec import encrypt_block, decrypt_block
from venture128.variables.constants import BLOCK_SIZE_BYTES

def ofb_encrypt(data: bytes, keys, iv = None) -> tuple[bytes, bytes]:

    # TODO IMPLEMENT
    # NOTE iv is 16 bytes
    
    return bytes(0), 0


def ofb_decrypt(data: bytes, keys, iv = None) -> bytes:
    
    # TODO IMPLEMENT
    # NOTE iv is 16 bytes
        
    return bytes(0)