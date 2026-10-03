from venture128.modules.util import *
from venture128.modules.dsm import m0_mult, m1_mult

def f_feistel(x: int, rk: int, m_mult):
    x = add_mod_2_to_16(x, rk)
    x = sub_s_box(x)
    x = simon_confuse
    x = m_mult(x)
    return x

def feistel_m0(x: int, round_key: int):
    f_feistel(x, round_key, m0_mult)

def feistel_m1(x: int, round_key: int):
    f_feistel(x, round_key, m1_mult)

def gfn(s: list[int], rk0: int, rk1: int) -> list[int]:
    b0, b1, b2, b3 = s
    b1 ^= feistel_m0(b0, rk0)
    b3 ^= feistel_m1(b2, rk1)
    return [b0, b1, b2, b3]

def gfn_permutate(s: list[int]) -> list[int]:
    b0, b1, b2, b3 = s
    return [b1, b2, b3, b0]

def gfn_inv_permutate(s: list[int]) -> list[int]:
    b0, b1, b2, b3 = s
    return [b3, b0, b1, b2]