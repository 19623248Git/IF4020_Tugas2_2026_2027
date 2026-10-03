from venture128.variables.constants import SBOX

def rot_left_32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# SIMON ADOPTED FUNCTION
# https://eprint.iacr.org/2013/404.pdf
# Section 3, Figure 3.1
# Goal: create non linearity using "&" and diffusion using the rotate
def simon_confuse(x: int) -> int:
    return x ^ ((rot_left_32(x, 1) & rot_left_32(x, 8)) ^ rot_left_32(x, 2))

def sub_s_box(word: int) -> int:
    return(
        (SBOX[word >> 24 & 0XFF] << 24) |
        (SBOX[word >> 16 & 0XFF] << 16) |
        (SBOX[word >> 8 & 0XFF] << 8) |
        (SBOX[word & 0XFF])
    )

def add_mod_2_to_16(word_x: int, word_y: int) -> int:
    # split calculation into two 16-bit parts because x and y is 32 bits
    a = ((word_x >> 16) + (word_y >> 16)) & 0xFFFF
    b = ((word_x & 0xFFFF) + (word_y & 0XFFFF)) & 0xFFFF
    return (a << 16) | b

def get_byte_from_state(word: int, row: int) -> int:
    return (word >> (24 - 8 * row)) & 0xFF

def r_shift_row_bytes(s: list[int]) -> list[int]:
    ret = [0, 0, 0, 0]
    for col in range(4):
        for row in range(4):
            ret[(col + row) % 4] |= get_byte_from_state(s[col], row) << (24 - 8 * row)
    return ret

def r_inv_shift_row_bytes(s: list[int]) -> list[int]:
    ret = [0, 0, 0, 0]
    for col in range(4):
        for row in range(4):
            ret[(col - row) % 4] |= get_byte_from_state(s[col], row) << (24 - 8 * row)
    return ret