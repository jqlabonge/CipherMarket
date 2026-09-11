"""
Pure-Python Keccak-256 (the original Keccak, i.e. Ethereum's keccak256 --
NOT the NIST-standardized SHA3-256, which uses different padding).
Used only for this sandbox's offline test harness (no network access to
install pysha3 / pycryptodome / eth-hash).
"""

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

MASK64 = (1 << 64) - 1


def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def keccak_f1600(state):
    # state: 5x5 list of lists, state[x][y], 64-bit lanes
    for rnd in range(24):
        # theta
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # rho + pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y % 5][(2 * x + 3 * y) % 5] = rol(state[x][y], ROT[x][y])

        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & MASK64) & B[(x + 2) % 5][y]

        # iota
        state[0][0] ^= RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes, for 256-bit output (capacity = 512 bits = 64 bytes)
    out_bytes = 32

    # pad10*1 with Keccak domain suffix 0x01
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]

    for offset in range(0, len(msg), rate):
        block = msg[offset:offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            x, y = i % 5, i // 5
            state[x][y] ^= lane
        keccak_f1600(state)

    out = bytearray()
    while len(out) < out_bytes:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += state[x][y].to_bytes(8, "little")
            if len(out) >= out_bytes:
                break
        if len(out) < out_bytes:
            keccak_f1600(state)
    return bytes(out[:out_bytes])
