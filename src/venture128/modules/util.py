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