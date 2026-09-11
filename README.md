# The Black Box Bazaar

- **Live app:** https://jqlabonge.github.io/CipherMarket/
- **Contract (Ethereum Sepolia, verified):** `0x83231B074245eBfCe03A2E804A35a621DBB9FAD8`
- **Block explorer:** https://sepolia.etherscan.io/address/0x83231B074245eBfCe03A2E804A35a621DBB9FAD8#code

## Vertical

An on-chain marketplace for cybersecurity vulnerability disclosure. A security
researcher (seller) has found a flaw in a wallet's signing process and wants to sell
the finding to that wallet (buyer) without revealing it up front. The flagship,
verified class is **ECDSA nonce reuse**: signing with the same random nonce (`k`)
twice lets anyone holding both signatures solve for the private key with pure
algebra, no brute force needed.

**The stakes are real.** In 2010, fail0verflow (and later George Hotz) discovered
Sony had signed every PlayStation 3 firmware update with the same ECDSA nonce
instead of a fresh one each time, letting them solve for Sony's private signing key
and sign their own "official" software. In 2013, a broken random number generator on
Android caused several Bitcoin wallet apps, including Blockchain.info's, to reuse
nonces, letting attackers recover users' private keys straight from public
blockchain data and drain their funds. Same failure both times: a repeated `k` turns
an unbreakable signature scheme into one that hands over the key for free, and it's
not just history. New wallets, hardware signers, and custom blockchain clients still
ship with broken or predictable random number generators today, so nonce reuse keeps
showing up in audits and post-mortems years after PS3 and Android made it famous.

Unlike most vulnerability classes, "is this claim real" has a deterministic
mathematical answer here: two signatures sharing an `r` either both `ecrecover` to
the target account or they don't, so the contract verifies the claim itself. No
oracle, no moderator. Seller stakes 10% and commits a hash of the finding; buyer pays
into escrow sight unseen; `reveal()` checks the math and pays the seller if it holds,
or refunds the buyer plus the seller's stake if it doesn't.

## Trust assumptions

- The check proves the target's key produced two colliding signatures, not a full
  audit of its signing history.
- `targetAccount` is asserted, not independently verified as a real wallet.
- Only `targetAccount` (or a delegate it authorizes) can purchase, enforced
  on-chain, so the market can't be used to buy leverage against someone else.
- Once revealed, a finding is public forever: buyers pay for first access, not
  permanent secrecy.

## Biggest design decision

The on-chain predicate is the nonce-reuse math itself (two `ecrecover` calls against
a shared `r`), not "seller reveals the private key, contract checks the address." A
raw key would be public in calldata the instant it's submitted, so a mempool bot
could steal it first. This also means there's no dispute process: `reveal()` is the
only path payment can take, so a sale resolves as either a proven finding (seller
paid) or a full refund plus the seller's slashed stake, never a payout followed by a
judgment call.

## Limitation

Only shared-`r` ECDSA nonce reuse is actually verified on-chain; other listed
categories (weak randomness, replay, malleability) are free-text with no matching
check, labeled "unverified" in the UI. A strike system backstops this: 2 failed
reveals permanently bans a seller address from listing, on-chain. Selling other
cybersecurity risks (logic bugs, access-control flaws, protocol-level exploits) is
the real goal long-term, but most of those can't reduce to one deterministic formula
the way nonce reuse can, so a future version would need an actual dispute path
(bonded reviewers ruling on the stake) instead of a contract deciding alone. For now,
only the one provable category is sold.

## Safety note

No real undisclosed vulnerabilities or private keys are used anywhere in this repo.
A nonce-reuse finding can't be faked with text the way other claims can: `reveal()`
only succeeds with two signatures that genuinely came from the target's real private
key. So every demo here uses a fresh, synthetic keypair generated client-side,
instead of pointing at any real account.
