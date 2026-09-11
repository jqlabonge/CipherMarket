# The Black Box Bazaar

An on-chain marketplace for buying and selling **cybersecurity risk**: specifically,
**cryptographic vulnerability disclosure**. The product being sold here isn't a
generic "info drop" wearing a security-themed label -- it's a specific class of
security finding (a live, exploitable weakness in how a wallet signs transactions),
sold through a mechanism built around how real vulnerability disclosure actually
works: a researcher (seller) has found a real, checkable cryptographic weakness in a
target account's signing process and wants to get paid by the affected wallet
(buyer) for it, without handing over the exploitable details for free before payment
clears -- the same "responsible disclosure vs. pay first" tension that shows up in
real bug-bounty and vulnerability-broker markets, just enforced by a contract instead
of a middleman's reputation. The flagship, fully-implemented vulnerability class is
**ECDSA nonce reuse** -- unlike most vulnerability classes, "did this seller actually
find a nonce-reuse bug against this target" has a deterministic mathematical answer
the contract itself can check with nothing but `ecrecover`. That's the whole point of
this design: a cybersecurity marketplace is only as trustworthy as its ability to
tell a real exploit from a bluff *before* money moves, and here that ability isn't a
policy or a moderator, it's a math check anyone can re-run.

## Deployed contract (Ethereum Sepolia)

- **Address:** `0x83231B074245eBfCe03A2E804A35a621DBB9FAD8`
- **Chain:** Ethereum Sepolia testnet, chain ID `11155111`
- **Block explorer (verified source):** https://sepolia.etherscan.io/address/0x83231B074245eBfCe03A2E804A35a621DBB9FAD8#code
- **Live app:** https://jqlabonge.github.io/CipherMarket/ (this address is the frontend's default -- no setup needed to browse or connect)

## How it works

1. **List.** Seller commits `keccak256(findingText)` plus public metadata
   (`targetAccount`, `category`, `severity`, `price`) and posts a 10% stake. The
   finding text itself isn't on-chain yet.
2. **Buy blind.** Only `targetAccount` -- or an address it has explicitly
   authorized via `authorizeBuyer()` -- can call `purchase()` and pay into escrow.
   Enforced on-chain (`isEligibleBuyer`), not just hidden in the UI. This keeps the
   marketplace from being a way to buy attack leverage against someone else's wallet.
3. **Reveal.** The full finding plus two `(messageHash, v, s)` signatures sharing
   one `r` get submitted on-chain -- automatically, usually within seconds of the
   purchase confirming. `reveal()` deliberately isn't restricted to the seller:
   the check is pure math (see below), so it doesn't matter who calls it, only
   whether the evidence is genuine. The contract checks the hash matches the
   commitment, the two messages differ, and `ecrecover` on both recovers to
   `targetAccount`. If it all checks out, escrow (price + stake) pays the seller
   and the finding is disclosed on-chain. If not, the buyer is refunded in full
   and gets the seller's slashed stake. If nobody reveals within the window,
   anyone can call `claimTimeout()`, which resolves it the same way as a failed
   reveal.

No off-chain oracle and no human referee are involved -- `ecrecover` is the entire
trust mechanism.

## Disputes: there aren't any

A normal marketplace needs a dispute process because "did the buyer actually get
what they paid for" is a judgment call somebody has to make after the fact. Here it
isn't a judgment call -- it's a hard on-chain precondition of the money moving at
all. `reveal()` is the only path payment can take: if the two signatures don't both
`ecrecover` to `targetAccount` over two different messages, the transaction doesn't
pay the seller, full stop -- the buyer is refunded and the seller's stake is slashed
to them automatically, in the same function call. There is no state where a payout
happens and *then* someone has to decide whether it was deserved. So buying a
listing isn't "trust the seller and hope" -- it's paying the contract to run the
verification for you: your purchase is what puts the finding in front of the
`ecrecover` check, and you either get a mathematically proven finding or your money
back plus the seller's stake. That's the trade being sold: not the finding itself,
but a transaction that cannot resolve in your favor unless the finding is real.

## Reputation and the strike system

Every seller address has an on-chain record (`reputationOf`) of how many of its
reveals were `verified` vs. `failed`, shown on every listing as a reputation score
and queryable directly via `reputationScoreBps()`. On top of that, `MAX_STRIKES = 2`:
once an address has accumulated 2 failed reveals -- bad math, a finding that doesn't
match its own commitment, or simply never revealing before the deadline -- it is
**permanently banned from creating new listings**, enforced inside `createListing()`
itself (`require(reputationOf[msg.sender].failed < MAX_STRIKES, ...)`), not just
hidden by the frontend. A banned address can still be revealed against, cancel, or
receive purchases  on anything already listed, it just can never post anything new.
Two strikes and you're out of the marketplace, permanently, with no admin override --
which is also why nobody is exposed to buying an already-publicly-known issue at a
premium: an inflated or recycled claim either passes the `ecrecover` check (in which
case it's genuinely proof of that target's key, regardless of how "well-known" the
underlying bug class is) or it fails and the seller is one strike closer to a
lifetime ban, so there's a real, escalating cost to listing anything that isn't real.

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
- `reveal()` accepts a call from anyone, not just the seller -- safe because
  correctness never depended on the caller, only on the math. An unauthorized
  caller submitting real evidence just relays what the seller already committed
  to; submitting fake evidence still fails the check and still gets the *seller's*
  stake slashed to the buyer, exactly like a seller-submitted bad reveal would.
  This is what lets the frontend auto-submit the reveal the instant a purchase
  confirms, from whichever wallet is already connected, instead of requiring the
  seller's own wallet to reconnect first. The one honest limit: this only makes
  it *instant* when the evidence-holder and the submitter are reachable from the
  same place (e.g. one browser demoing both sides) -- in a real two-stranger
  deployment, the evidence still has to reach whoever submits it somehow; no
  contract change removes that.

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
one's own specific math/protocol check individually. The frontend deliberately
labels those other categories "unverified -- stake only" in the listing form so a
buyer never mistakes them for something `ecrecover` actually checked; the strike
system (above) is what stands in for verification there, since an unverified,
low-quality, or bad-faith listing in those categories still counts as a failed
reveal against the seller's two-strike limit the moment a buyer forces a reveal
that doesn't hold up.

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

Already deployed at the address above -- the frontend defaults to it, so this is
only needed to redeploy your own copy:

```bash
cd hardhat
npm install
cp .env.example .env        # fill in SEPOLIA_RPC_URL and PRIVATE_KEY (testnet funds only!)
npx hardhat run scripts/deploy.js --network sepolia
npx hardhat verify --network sepolia <printed address>
```

Paste the printed address into the frontend's "Deployed BlackBoxBazaar address"
field (or update `DEFAULT_CONTRACT_ADDRESS` in `frontend/index.html`). Chain:
Ethereum Sepolia (`11155111`). Explorer:
`https://sepolia.etherscan.io/address/<contract address>`.

Base Sepolia is also configured in `hardhat.config.js` as an alternative --
fill in `BASE_SEPOLIA_RPC_URL`/`PRIVATE_KEY` and run against `--network
baseSepolia` (chain ID `84532`).

## Safety note

No real undisclosed vulnerabilities, real private keys, or operational exploit
material are used anywhere in this repo. The "vulnerable target" in every demo
path is a freshly generated, synthetic keypair created client-side for that run only.
