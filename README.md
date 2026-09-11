# The Black Box Bazaar

An on-chain marketplace for **cryptographic vulnerability disclosure**. A security
researcher (seller) has found a real, checkable cryptographic weakness in a target
account's signing process and wants to sell the finding to the affected wallet/protocol
(buyer) without revealing it up front -- revealing it for free destroys its value. The
flagship, fully-implemented vulnerability class is **ECDSA nonce reuse**, because unlike
most vulnerability classes, "did this seller actually find a nonce-reuse bug against
this specific target" has a deterministic mathematical answer the contract itself can
check with nothing but `ecrecover`.

## 1. Chosen vertical

**Applied-cryptography vulnerability disclosure**, specifically **ECDSA nonce reuse**.
If a signer ever reuses the same nonce `k` across two signatures over different
messages, both signatures share the same `r` (the x-coordinate of `k*G`). That is
mathematically almost impossible to happen by accident with two *different* nonces
(it would mean solving the discrete-log problem), so "two valid signatures from the
same public key, over two different messages, sharing one `r`" is a sound, checkable
proxy for "nonce reuse occurred." Other vulnerability classes in the same product
(weak randomness, replay bugs, signature malleability) are supported by the data
model (`category` is a free string) but only nonce reuse has an implemented, verified
on-chain predicate in this MVP -- see Limitation, below.

## 2. How the black-box marketplace works

1. **List.** A seller commits to a complete finding by submitting
   `keccak256(findingText)` as the listing's `commitmentHash`, along with public,
   non-sensitive metadata: `targetAccount`, `category`, `severity`, `title`, `price`.
   They also post a stake (10% of price) as a good-faith bond. The full finding text
   is **not** stored on-chain yet.
2. **Buy blind.** A buyer pays `price` into escrow via `purchase()`, before seeing
   anything but the public metadata.
3. **Reveal.** The seller calls `reveal()` with the full finding text plus the actual
   cryptographic evidence: two `(messageHash, v, s)` triples sharing one `r`. The
   contract checks, in order:
   - `keccak256(findingText) == commitmentHash` -- the revealed text is what was
     promised at listing time (this step only proves *consistency*, not truth --
     see the note on commitments below);
   - the two message hashes are different;
   - `ecrecover(msgHash1, v1, r, s1) == targetAccount` **and**
     `ecrecover(msgHash2, v2, r, s2) == targetAccount`.

   If every check passes, escrow (price + stake) releases to the seller, the finding
   becomes disclosed on-chain, and the seller's reputation improves. If any check
   fails, the sale is rejected automatically: the buyer is refunded in full **and**
   receives the seller's slashed stake as compensation. If the seller never calls
   `reveal()` within the 1-hour window, anyone can call `claimTimeout()`, which
   resolves the sale exactly like a failed reveal.

No off-chain oracle and no human referee are involved in the ECDSA verification at
any point -- `ecrecover` is the entire trust mechanism for the supported claim.

## 3. How ECDSA nonce-reuse verification works (high level)

For a signature `(r, s)` over hash `h` with nonce `k` and private key `d`:
`s = k⁻¹(h + r·d) mod n`. If the same `k` signs a second message `h2`, you get
`s2 = k⁻¹(h2 + r·d) mod n` with the **same** `r` (since `r` depends only on `k`).
Anyone holding both signatures can solve for `k` and then `d` directly -- that's the
real-world danger nonce reuse creates, and it's the reason a seller wouldn't want to
publish the evidence before being paid.

The contract does **not** need to compute `d` on-chain to verify the claim (and
deliberately doesn't -- see Trust Assumptions). It only needs to confirm that the two
signatures are both genuinely signed by `targetAccount`'s key, over different
messages, sharing an `r`. `ecrecover` alone answers "did `targetAccount`'s key
produce this signature," and running it twice against the two supplied signatures is
sufficient to make the nonce-reuse claim mathematically checkable.

## 4. Trust assumptions

- **What the on-chain check actually proves.** It proves `targetAccount`'s private
  key produced two signatures, over two different messages, that share an `r`. Given
  how astronomically unlikely that is to happen with two independent, honestly
  generated nonces, this is strong evidence of nonce reuse -- but it is evidence
  about *these two signatures*, not a general audit of the target's entire signing
  history or codebase.
- **Commitment ≠ truth.** The `commitmentHash` check only proves the seller didn't
  swap the finding text after listing -- it says nothing about whether the finding
  is real. The cryptographic evidence check is what actually establishes the claim;
  the commitment exists purely so the buyer can trust the *content* they're about to
  pay for hasn't been altered mid-flight.
- **The target address is asserted, not audited.** Nothing on-chain confirms
  `targetAccount` corresponds to a real, meaningful wallet/protocol signer (e.g. a
  known deployer key) rather than a burner address the seller controls themselves --
  a seller could list against their own throwaway key and "solve" their own
  challenge to farm reputation. Buyers are expected to independently confirm what
  `targetAccount` actually is before trusting a listing.
- **The stake, not the contract, discourages spam/bad-faith listings** -- the
  protocol can't know in advance whether a claim is real; it only makes a false one
  costly after the fact.
- **Public disclosure loses secrecy once verified.** Once `reveal()` succeeds, the
  finding is public on-chain forever (any chain data is). The buyer paid for
  first/exclusive access before that point, not for permanent secrecy afterward.

## 5. Biggest design decision

The core decision was making the **on-chain predicate itself the nonce-reuse math**
(two `ecrecover` calls against a shared `r`), instead of the more obvious "seller
reveals the recovered private key, contract checks `address(key) == target`."
Revealing the raw private key on-chain is fatal to a marketplace like this: the
instant it's included in a transaction it's public in calldata forever, so a
malicious buyer's mempool-watching bot could read it and use it before paying (or
without ever paying). Requiring the seller to submit the original *signature pair*
instead means the contract can verify the claim using exactly the evidence a real
victim's monitoring system would also see -- and it keeps verification symmetric
with how the vulnerability would actually be discovered in the wild (someone
noticing two signatures share an `r`), rather than inventing an artificial
challenge-response ritual.

## 6. One important limitation

**This mechanism is not a universal cryptographic-vulnerability verifier.** It
implements one deterministic, well-defined mathematical predicate: shared-`r`
ECDSA nonce reuse against a named target address. Other vulnerability classes this
marketplace's data model *lists* as supported categories -- weak/predictable
randomness in key generation, replay vulnerabilities, signature malleability --
each have their own, different verification predicates (or, for some, no fully
deterministic on-chain predicate at all; a replay bug might require replaying a
transaction against a specific contract's state, which isn't just a pure math
check). Extending real, trustless, oracle-free verification to those classes would
require implementing each one's specific mathematical or protocol-level check
individually -- this MVP deliberately does that for nonce reuse only, since it's
the cleanest example of the underlying idea ("the smart contract itself can verify
a specific class of cryptographic claim") and is honest about not overreaching into
classes that would quietly need a human judgment call in disguise.

## 7. Repo layout

```
contracts/BlackBoxBazaar.sol   The marketplace contract (single source of truth)
build/                         Compiled ABI + bytecode (solc --via-ir, verified to compile clean)
test/                          Offline, dependency-free Python test harness (see below)
hardhat/                       Hardhat project: real Solidity test suite + Base Sepolia deploy script
frontend/                      Zero-npm-dependency static web app (ethers.js via CDN)
agents/                        (buyer agent is built into frontend/index.html's "Autonomous Agents" tab)
```

### Why there are two test setups

This project was built inside a network-sandboxed environment whose egress
allowlist blocks the npm registry, PyPI, and essentially every RPC endpoint (only
`github.com` over git was reachable). That made a normal `npx hardhat test` run
impossible to execute *in that sandbox*. Rather than skip testing, the contract's
core cryptographic predicate was validated with a **from-scratch, dependency-free
Python implementation of secp256k1 and Keccak-256** (`test/secp256k1.py`,
`test/keccak_pure.py`), each checked against published test vectors, and then used
to run `test/test_nonce_reuse.py` end-to-end against the exact logic
`reveal()` implements -- genuine nonce reuse verifies, a wrong key rejects, a
tampered finding rejects. Run it yourself:

```bash
cd test && python3 test_nonce_reuse.py
```

The Solidity contract itself was compiled for real with `solc` in that same
sandbox (catching and fixing a genuine "stack too deep" error along the way --
fixed by enabling `viaIR`). The **`hardhat/`** directory has the real Hardhat test
suite (`hardhat/test/BlackBoxBazaar.test.js`) that exercises the actual deployed
bytecode end-to-end (happy path, invalid signature, mismatched commitment,
timeout, cancellation) -- run this on a machine with normal network access:

```bash
cd hardhat
npm install
npx hardhat test
```

## 8. Running the frontend locally

The frontend has **zero npm dependencies** (ethers.js loads from a CDN at
runtime in the browser), so `npm install` succeeds instantly even without
network access to a package registry:

```bash
cd frontend
npm install
npm run dev
```

Open the printed `http://localhost:5173` URL. Paste in a deployed contract
address (see below), connect MetaMask, and:
- **Marketplace tab** -- browse listings, buy, see disclosed findings, claim
  timeouts.
- **Sell a Finding tab** -- create a listing (commits a hash only) and, after a
  buyer purchases, submit the reveal.
- **Autonomous Agents tab** -- a deterministic buyer agent that scans all
  listings and auto-purchases anything matching a simple rule (e.g. "category
  contains ECDSA Nonce Reuse, severity Critical, price <= 0.02 ETH"), with a live
  log of its decisions. This demonstrates agent-to-agent commerce without a human
  clicking "buy."
- **Simulate Vulnerable Target tab** -- generates a synthetic keypair and uses a
  small, clearly-labeled toy signer (`frontend/toy-vulnerable-signer.js`, no
  dependencies, runs entirely in your browser) that intentionally reuses a nonce
  across two demo messages, so you have a genuine nonce-reuse finding to list and
  reveal without touching any real key. One click sends the generated evidence
  straight into the Sell/Reveal forms.

## 9. Deploying to Base Sepolia

```bash
cd hardhat
npm install
cp .env.example .env        # fill in PRIVATE_KEY (testnet funds only!)
npx hardhat run scripts/deploy.js --network baseSepolia
```

Then paste the printed contract address into the frontend's "Deployed
BlackBoxBazaar address" field.

- **Deployed application URL:** _fill in after hosting `frontend/` (e.g. GitHub
  Pages, Vercel, or any static host)_
- **Testnet contract address:** _fill in after running the deploy script_
- **Chain:** Base Sepolia (chain ID `84532`)
- **Block explorer:** `https://sepolia.basescan.org/address/<contract address>`

## 10. Safety note

No real undisclosed vulnerabilities, real private keys, or operational exploit
material are used anywhere in this repo. The "vulnerable target" in every demo
path is a freshly generated, synthetic keypair created client-side for that demo
run only.
