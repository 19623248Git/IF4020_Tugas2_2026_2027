def rot_left_32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# SIMON ADOPTED FUNCTION
# https://eprint.iacr.org/2013/404.pdf
# Section 3, Figure 3.1
# Goal: create non linearity using "&" and diffusion using the rotate
def simon_confuse(x: int) -> int:
    return x ^ ((rot_left_32(x, 1) & rot_left_32(x, 8)) ^ rot_left_32(x, 2))

