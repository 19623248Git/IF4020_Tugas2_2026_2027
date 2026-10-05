# using dsm gallois field multiplier
# so the sbox is using poly 0x11D
from venture128.variables.constants import DSM_GF_MULT_TABLE as gf_mult

rots = [0, 2, 4, 6, 7]

def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF

def gf_inverse(a: int) -> int:
    a = a & 0xFF
    if(a == 0):
        return 0
    for b in range(1, 256):
        if gf_mult[a][b] == 1:
            return b

def affine(b: int, c: int):
    b = b & 0xFF
    y = 0
    for r in rots:
        y ^= rotl8(b, r)
    return y ^ c

def is_valid(c: int):
    # checks if s[x] == x or s[x] == ~x exists
    # if exists then the sbox is not valid
    c = c & 0xFF
    for x in range (256):
        s = affine(gf_inverse(x), c)
        if s == x or s == x ^ 0xFF:
            return False
    return True

def find_consts():
    ret = []
    for c in range (256):
        if is_valid(c):
            ret.append(c)
    print([hex(c) for c in ret])

def gen_s_box(c: int):
    c = c & 0xFF
    s_box = [affine(gf_inverse(x), c) for x in range(256)]
    print("SBOX = [")
    for row in range(16):
        print("    " + " ".join(f"0x{s:02X}," for s in s_box[row * 16:(row + 1) * 16]))
    print("]")

def generate_s_box():
    CONST = 0xe5
    gen_s_box(CONST)