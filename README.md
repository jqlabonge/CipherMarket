# The Black Box Bazaar

An on-chain marketplace for **cryptographic vulnerability disclosure**. A security
researcher (seller) has found a real, checkable cryptographic weakness in a target
account's signing process and wants to sell the finding to the affected wallet
(buyer) without revealing it up front. The flagship, fully-implemented vulnerability
class is **ECDSA nonce reuse** -- unlike most vulnerability classes, "did this seller
actually find a nonce-reuse bug against this target" has a deterministic
mathematical answer the contract itself can check with nothing but `ecrecover`.

## How it works

1. **List.** Seller commits `keccak256(findingText)` plus public metadata
   (`targetAccount`, `category`, `severity`, `price`) and posts a 10% stake. The
   finding text itself isn't on-chain yet.
2. **Buy blind.** Only `targetAccount` -- or an address it has explicitly
   authorized via `authorizeBuyer()` -- can call `purchase()` and pay into escrow.
   Enforced on-chain (`isEligibleBuyer`), not just hidden in the UI. This keeps the
   marketplace from being a way to buy attack leverage against someone else's wallet.
3. **Reveal.** Seller submits the full finding plus two `(messageHash, v, s)`
   signatures sharing one `r`. The contract checks the hash matches the commitment,
   the two messages differ, and `ecrecover` on both recovers to `targetAccount`. If
   it all checks out, escrow (price + stake) pays the seller and the finding is
   disclosed on-chain. If not, the buyer is refunded in full and gets the seller's
   slashed stake. If the seller never reveals within the window, anyone can call
   `claimTimeout()`, which resolves it the same way as a failed reveal.

No off-chain oracle and no human referee are involved -- `ecrecover` is the entire
trust mechanism.

## Why this verifies cleanly

For a signature `(r, s)` over hash `h` with nonce `k` and private key `d`:
`s = k⁻¹(h + r·d) mod n`. Reusing `k` for a second message `h2` produces a second
signature with the **same** `r`. Given two signatures like that, the contract
doesn't need to compute the private key itself -- it only needs to confirm both
signatures genuinely came from `targetAccount`'s key, over two different messages,
sharing an `r`. Two `ecrecover` calls are sufficient to make that claim
mathematically checkable, without ever putting a raw private key on-chain (which
would leak it to anyone watching the mempool before the seller got paid).

## Trust assumptions

- The on-chain check proves `targetAccount`'s key produced two signatures sharing
  an `r` -- strong evidence of nonce reuse, but evidence about *these two
  signatures*, not a full audit of the target's signing history.
- The commitment hash only proves the seller didn't swap the finding text after
  listing -- it's the signature check that actually proves the claim.
- `targetAccount` is asserted, not independently audited as a "real" wallet.
- The stake discourages bad-faith listings after the fact; the protocol can't know
  in advance whether a claim is real.
- Once `reveal()` succeeds, the finding is public on-chain forever -- the buyer
  paid for first/exclusive access, not permanent secrecy.
- `purchase`, `reveal`, `cancelListing`, and `claimTimeout` follow
  checks-effects-interactions, plus a `nonReentrant` guard as defense-in-depth.

## Biggest design decision

The on-chain predicate is the nonce-reuse math itself (two `ecrecover` calls
against a shared `r`), not "seller reveals the recovered private key, contract
checks the address matches." Revealing a raw private key on-chain would be fatal
here -- it's public in calldata the instant it's submitted, so a mempool-watching
bot could steal it before the seller gets paid. Requiring the original signature
pair instead means verification uses exactly the evidence a real victim would see
in the wild.

## Limitation

This implements one deterministic predicate: shared-`r` ECDSA nonce reuse. Other
categories the data model allows as free-text (weak randomness, replay bugs,
signature malleability) don't have an implemented on-chain check in this MVP --
extending real, oracle-free verification to those would mean implementing each
one's own specific math/protocol check individually.

## Repo layout

```
contracts/BlackBoxBazaar.sol   The marketplace contract
build/                         Compiled ABI + bytecode
test/                          Offline, dependency-free Python test harness
hardhat/                       Hardhat project: Solidity test suite + Sepolia deploy script
frontend/                      Zero-npm-dependency static web app (ethers.js via CDN)
```

## Testing

Built in a network-sandboxed environment where `npm`/PyPI/RPC access wasn't
reachable, so the core cryptographic predicate was independently validated with a
from-scratch, dependency-free Python implementation of secp256k1 and Keccak-256,
checked against published test vectors:

```bash
cd test && python3 test_nonce_reuse.py
```

The real Hardhat suite (`hardhat/test/BlackBoxBazaar.test.js`) exercises the
actual deployed bytecode end to end -- run on a machine with normal network access:

```bash
cd hardhat && npm install && npx hardhat test
```

## Running the frontend

Zero npm dependencies (ethers.js loads from a CDN at runtime):

```bash
cd frontend && npm install && npm run dev
```

Open the printed `localhost` URL, paste in a deployed contract address, connect
MetaMask, and use the in-app "Protocol flow" / "New here?" panels -- they walk
through the whole flow so this README doesn't have to. Highlights: a live stats
strip and activity feed computed from on-chain events; a Marketplace tab that
groups listings by your relationship to them; a Sell tab for listing + revealing;
an Autonomous Agents tab with a Seller Agent (auto-reveals the moment its listing
is bought, no human step) and a Buyer Agent (auto-purchases anything matching a
rule you set); and a Simulate Vulnerable Target tab that generates a synthetic
nonce-reuse finding client-side, with no real key ever involved.

### Full demo, both resolution paths

**Successful reveal:** list against a synthetic target you hold the key for (via
Seller Agent, or Simulate + Sell), import that throwaway key into a second demo
MetaMask account, fund it with a trace of Sepolia ETH, and buy as that account --
the reveal recovers cleanly and the listing goes `Verified`.

**Failed reveal:** list a finding targeting a wallet you *don't* hold the key
for (e.g. a second MetaMask account you control as buyer, but not as the
"vulnerable" signer). It's still eligible to purchase, but any reveal attempt
can't produce a genuinely matching signature, so it resolves `Failed` and the
buyer is refunded price + stake.

## Deploying to Sepolia

```bash
cd hardhat
npm install
cp .env.example .env        # fill in SEPOLIA_RPC_URL and PRIVATE_KEY (testnet funds only!)
npx hardhat run scripts/deploy.js --network sepolia
```

Paste the printed address into the frontend's "Deployed BlackBoxBazaar address"
field. Chain: Ethereum Sepolia (`11155111`). Explorer:
`https://sepolia.etherscan.io/address/<contract address>`.

Base Sepolia is also configured in `hardhat.config.js` as an alternative --
fill in `BASE_SEPOLIA_RPC_URL`/`PRIVATE_KEY` and run against `--network
baseSepolia` (chain ID `84532`).

## Safety note

No real undisclosed vulnerabilities, real private keys, or operational exploit
material are used anywhere in this repo. The "vulnerable target" in every demo
path is a freshly generated, synthetic keypair created client-side for that run only.
