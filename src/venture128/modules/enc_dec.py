from venture128.modules.util import r_shift_row_bytes, r_inv_shift_row_bytes, whiten
from venture128.modules.type2_gfn import gfn, gfn_permutate, gfn_inv_permutate

def bytes_to_state(block: bytes) -> list[int]:
    return [int.from_bytes(block[4 * j:4 * j + 4], "big") for j in range(4)]


def state_to_bytes(state: list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "big") for word in state)


def encrypt_block(block: bytes, round_keys) -> bytes:
    # whitening at start and end of encryption
    wk_pre, rk, wk_post = round_keys
    s = whiten(bytes_to_state(block), wk_pre)
    for r in range(len(rk) // 2):
        if r % 2 == 0:
            """
            only shift row for even rounds
            if we always shift row at every round, then:
                1. b0 row 1
                2. b0 row 3
                3. b2 row 1
                4. b2 row 3 
            will never reach the fesitel function
            Data example: 
                    B0   B1   B2   B3
            row 0 [ 00   04   08   0C ]
            row 1 [ 01   05   09   0D ]
            row 2 [ 02   06   0A   0E ]
            row 3 [ 03   07   0B   0F ]
            """
            s = r_shift_row_bytes(s)
        s = gfn(s, rk[2 * r], rk[2 * r + 1])
        s = gfn_permutate(s)
    return state_to_bytes(whiten(s, wk_post))


def decrypt_block(block: bytes, round_keys) -> bytes:
    # reverse whitening at start and end of decryption
    wk_pre, rk, wk_post = round_keys
    s = whiten(bytes_to_state(block), wk_post)
    for r in reversed(range(len(rk) // 2)):
        s = gfn_inv_permutate(s)
        s = gfn(s, rk[2 * r], rk[2 * r + 1])
        if r % 2 == 0:
            # because of encryption rule
            s = r_inv_shift_row_bytes(s)
    return state_to_bytes(whiten(s, wk_pre))