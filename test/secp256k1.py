"""
Minimal, dependency-free secp256k1 ECDSA implementation used ONLY to build
and validate the local test harness (test_nonce_reuse.py) in this sandbox,
which has no network access to install real crypto libraries (web3.py,
eth-account, coincurve, etc. are all unreachable here). It mirrors exactly
the math the Solidity contract performs (sign, recover-via-ecrecover-
equivalent), so a pass here is strong evidence the on-chain predicate is
correct. It is NOT used by the frontend or the deployed contract -- the
frontend uses ethers.js (loaded from a CDN in the user's own browser) for
all real signing, and the contract uses the EVM's native `ecrecover`.
"""

# secp256k1 curve parameters (standard, SEC 2)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def inv_mod(a, m):
    return pow(a, m - 2, m)


def is_infinity(pt):
    return pt is None


def point_add(p1, p2):
    if is_infinity(p1):
        return p2
    if is_infinity(p2):
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_address_pubkey(d):
    """Return (x, y) uncompressed public key point for private key d."""
    return point_mul(d, G)


def eth_address_from_pubkey(pt):
    """Compute the last-20-bytes-of-keccak256 Ethereum address.
    Uses a pure-python keccak implementation for this offline sanity check.
    """
    from keccak_pure import keccak256

    x, y = pt
    pub_bytes = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    digest = keccak256(pub_bytes)
    return "0x" + digest[-20:].hex()


def ecdsa_sign(d, h_int, k):
    """Sign integer message hash h_int with private key d and nonce k.
    Returns (r, s, v) exactly like a real ECDSA signature; v in {27, 28}.
    """
    R = point_mul(k, G)
    r = R[0] % N
    assert r != 0
    k_inv = inv_mod(k, N)
    s = (k_inv * (h_int + r * d)) % N
    y_parity = R[1] % 2
    # Canonicalize to low-s (as Ethereum does) and flip parity if we flip s.
    if s > N // 2:
        s = N - s
        y_parity ^= 1
    v = 27 + y_parity
    return r, s, v


def ecdsa_recover(h_int, v, r, s):
    """Recover the public key point from a signature, mirroring `ecrecover`."""
    if r == 0 or r >= N or s == 0 or s >= N:
        return None
    y_parity = v - 27
    x = r
    # y^2 = x^3 + 7 mod P
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)  # P % 4 == 3, so this gives a square root
    if (y % 2) != y_parity:
        y = P - y
    R = (x, y)

    r_inv = inv_mod(r, N)
    h = h_int % N
    # pubkey = r^-1 * (s*R - h*G)
    sR = point_mul(s, R)
    hG = point_mul(h, G)
    neg_hG = (hG[0], (P - hG[1]) % P) if hG else None
    combined = point_add(sR, neg_hG)
    pub = point_mul(r_inv, combined)
    return pub
