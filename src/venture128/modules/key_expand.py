from venture128.variables.constants import KEY_SIZE_BYTES, MAX_ROUNDS, ROUNDS, RCON
from venture128.modules.util import sub_s_box, rot_left_32

def key_expansion(master_key: bytes) -> list[int]:
    # AES-128 key expansion
    if len(master_key) != KEY_SIZE_BYTES:
        raise ValueError(f"key is not {KEY_SIZE_BYTES}")
    w = [int.from_bytes(master_key[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = sub_s_box(rot_left_32(temp, 8)) ^ (RCON[(i // 4) - 1] << 24)
        w.append(w[i - 4] ^ temp)
    return w

def generate_round_keys(master_key: bytes, n: int = ROUNDS):
    # only return up to n rounds
    if not 1 <= n <= MAX_ROUNDS:
        raise ValueError(f"Rounds only between 1 and {MAX_ROUNDS}")
    w = key_expansion(master_key)
    return w[0:4], w[4:4 + (2 * n)], w[40:44]