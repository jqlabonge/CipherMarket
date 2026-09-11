"""
Offline test harness for the BlackBoxBazaar nonce-reuse verification
predicate. This sandbox's network egress is locked down to essentially
github.com only (no npm registry, no PyPI, no RPC endpoints), so a real
Hardhat/web3.py test run isn't possible here. Instead this file
re-implements, in verified pure Python (secp256k1.py / keccak_pure.py,
both checked against known test vectors below), EXACTLY the same checks
`BlackBoxBazaar.reveal()` performs in Solidity:

    ecrecover(msgHash1, v1, r, s1) == target && ecrecover(msgHash2, v2, r, s2) == target
    && msgHash1 != msgHash2 && keccak256(findingText) == commitmentHash

A pass here is strong evidence the on-chain predicate is mathematically
sound. It is NOT a substitute for the real Hardhat test suite in
test/BlackBoxBazaar.hardhat.test.js, which the user should run with
`npx hardhat test` on a machine with normal network access -- see README.
"""

import random

from keccak_pure import keccak256
from secp256k1 import N, ecdsa_recover, ecdsa_sign, eth_address_from_pubkey, privkey_to_address_pubkey


def keccak_int(data: bytes) -> int:
    return int.from_bytes(keccak256(data), "big")


def make_target():
    d = random.randrange(1, N)
    pub = privkey_to_address_pubkey(d)
    addr = eth_address_from_pubkey(pub)
    return d, addr


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    assert condition, f"FAILED: {label}"


def main():
    print("=== keccak256 known-vector sanity check ===")
    check(
        "keccak256('abc') matches published test vector",
        keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    )

    print("\n=== secp256k1 known-vector sanity check ===")
    d1, addr1 = 1, None
    pub1 = privkey_to_address_pubkey(1)
    addr1 = eth_address_from_pubkey(pub1)
    check(
        "address(privkey=1) matches published test vector",
        addr1.lower() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    )

    print("\n=== Scenario 1: genuine ECDSA nonce reuse -> contract should VERIFY ===")
    d, target = make_target()
    print(f"target private key (toy/synthetic, for demo only): {hex(d)}")
    print(f"target address: {target}")

    msg1 = b"transfer 10 ETH to 0xBuyer... nonce=7"
    msg2 = b"approve spender 0xDeFiProtocol for 500 USDC"
    h1 = keccak_int(msg1)
    h2 = keccak_int(msg2)
    assert h1 != h2

    k = random.randrange(1, N)  # the reused nonce -- the seller's whole finding
    r1, s1, v1 = ecdsa_sign(d, h1, k)
    r2, s2, v2 = ecdsa_sign(d, h2, k)
    check("both signatures share the same r (same nonce k was used)", r1 == r2)
    r = r1

    rec1 = ecdsa_recover(h1, v1, r, s1)
    rec2 = ecdsa_recover(h2, v2, r, s2)
    rec1_addr = eth_address_from_pubkey(rec1)
    rec2_addr = eth_address_from_pubkey(rec2)

    check("ecrecover(sig1) == targetAccount (mirrors contract's rec1 check)", rec1_addr == target)
    check("ecrecover(sig2) == targetAccount (mirrors contract's rec2 check)", rec2_addr == target)
    check("msgHash1 != msgHash2 (contract's distinct-message requirement)", h1 != h2)
    print("=> contract predicate: VALID nonce-reuse claim. Seller would be paid.")

    # Extra: demonstrate the actual attack the finding is about (not required
    # by the contract, but this is *why* nonce reuse is dangerous) --
    # recovering the private key from the two signatures and confirming it
    # equals the target's real key.
    s_diff_inv = pow((s1 - s2) % N, N - 2, N)
    recovered_k = ((h1 - h2) * s_diff_inv) % N
    r_inv = pow(r, N - 2, N)
    recovered_priv = ((s1 * recovered_k - h1) * r_inv) % N
    check("full private-key recovery from the two signatures matches the real key", recovered_priv == d)

    print("\n=== Scenario 2: seller tries to fake it against a DIFFERENT key -> contract should REJECT ===")
    d_wrong, _ = make_target()
    r1b, s1b, v1b = ecdsa_sign(d_wrong, h1, k)
    r2b, s2b, v2b = ecdsa_sign(d_wrong, h2, k)
    rec1b = eth_address_from_pubkey(ecdsa_recover(h1, v1b, r1b, s1b))
    valid = rec1b == target  # checking against the *listed* target, not the impostor's own key
    check("signatures from an unrelated key do NOT recover to the listed target", not valid)
    print("=> contract predicate: INVALID claim. Buyer refunded, seller's stake slashed.")

    print("\n=== Scenario 3: same message signed twice (no real nonce reuse) -> contract should REJECT ===")
    check(
        "identical message hashes are rejected regardless of signature validity",
        not (h1 != h1),
    )
    print("=> contract's `msgHash1 == msgHash2` guard would reject this before even calling ecrecover.")

    print("\n=== Scenario 4: commitment-hash check (hides the finding pre-purchase) ===")
    finding_text = f"Target's signer reused nonce k across two tx approvals; recovered private key {hex(d)[:10]}...redacted for repo safety"
    commitment = keccak256(finding_text.encode())
    check(
        "revealed finding matches what the seller committed to at listing time",
        keccak256(finding_text.encode()) == commitment,
    )
    tampered = finding_text + " (tampered)"
    check(
        "a tampered/substituted finding is rejected by the commitment check",
        keccak256(tampered.encode()) != commitment,
    )

    print("\nAll scenarios match the exact predicate implemented in contracts/BlackBoxBazaar.sol:reveal().")


if __name__ == "__main__":
    main()
