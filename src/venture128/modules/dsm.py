from venture128.variables.constants import DSM_GF_MULT_TABLE

# DIFUSION SWITCHING MECHANISM
# Source: https://www.rfc-editor.org/info/rfc6114/#section-4.4 

# more efficient
G2 = DSM_GF_MULT_TABLE[0x02]
G4 = DSM_GF_MULT_TABLE[0x04]
G6 = DSM_GF_MULT_TABLE[0x06]
G8 = DSM_GF_MULT_TABLE[0x08]
GA = DSM_GF_MULT_TABLE[0x0A]


def m0_mult(x: int):
    T0 = (x >> 24) & 0xFF
    T1 = (x >> 16) & 0xFF
    T2 = (x >> 8) & 0xFF
    T3 = x & 0xFF
    y0 = T0 ^ G2[T1] ^ G4[T2] ^ G6[T3]
    y1 = G2[T0] ^ T1 ^ G6[T2] ^ G4[T3]
    y2 = G4[T0] ^ G6[T1] ^ T2 ^ G2[T3]
    y3 = G6[T0] ^ G4[T1] ^ G2[T2] ^ T3
    return (y0 << 24) | (y1 << 16) | (y2 << 8) | y3


def m1_mult(x: int):
    T0 = (x >> 24) & 0xFF
    T1 = (x >> 16) & 0xFF
    T2 = (x >> 8) & 0xFF
    T3 = x & 0xFF
    y0 = T0 ^ G8[T1] ^ G2[T2] ^ GA[T3]
    y1 = G8[T0] ^ T1 ^ GA[T2] ^ G2[T3]
    y2 = G2[T0] ^ GA[T1] ^ T2 ^ G8[T3]
    y3 = GA[T0] ^ G2[T1] ^ G8[T2] ^ T3
    return (y0 << 24) | (y1 << 16) | (y2 << 8) | y3
