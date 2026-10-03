from venture128.variables.constants import BLOCK_SIZE_BYTES

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid PKCS#7 length")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-n]