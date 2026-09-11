const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

// --- minimal raw secp256k1 signer, used ONLY so this test suite can
// construct a genuine nonce-reuse signature pair (two signatures over
// different messages sharing one `r`). Real wallets (ethers' normal
// Wallet.signMessage, MetaMask, etc.) derive nonces deterministically per
// RFC 6979 specifically so this never happens by accident -- so to test the
// vulnerability class at all we need a signer that can be told "reuse this
// nonce". This mirrors frontend/toy-vulnerable-signer.js exactly. ---
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n % P;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n % P;
const G = [GX, GY];

function mod(a, m) { const r = a % m; return r >= 0n ? r : r + m; }
function invMod(a, m) { return powMod(mod(a, m), m - 2n, m); }
function powMod(base, exp, m) {
  let result = 1n; base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n; base = mod(base * base, m);
  }
  return result;
}
function pointAdd(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2, P) === 0n) return null;
  let lam;
  if (x1 === x2 && y1 === y2) lam = mod(3n * x1 * x1 * invMod(2n * y1, P), P);
  else lam = mod((y2 - y1) * invMod(mod(x2 - x1, P), P), P);
  const x3 = mod(lam * lam - x1 - x2, P);
  const y3 = mod(lam * (x1 - x3) - y1, P);
  return [x3, y3];
}
function pointMul(k, pt) {
  let result = null, addend = pt;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}
function rawSign(privHex, msgHashHex, kHex) {
  const d = BigInt(privHex), h = BigInt(msgHashHex), k = BigInt(kHex);
  const R = pointMul(k, G);
  const r = mod(R[0], N);
  const kInv = invMod(k, N);
  let s = mod(kInv * (h + r * d), N);
  let yParity = Number(mod(R[1], 2n));
  if (s > N / 2n) { s = N - s; yParity ^= 1; }
  const v = 27 + yParity;
  return {
    r: '0x' + r.toString(16).padStart(64, '0'),
    s: '0x' + s.toString(16).padStart(64, '0'),
    v,
  };
}
function addressFromPriv(privHex) {
  const d = BigInt(privHex);
  const pub = pointMul(d, G);
  const xHex = pub[0].toString(16).padStart(64, '0');
  const yHex = pub[1].toString(16).padStart(64, '0');
  const digest = ethers.keccak256('0x' + xHex + yHex);
  return ethers.getAddress('0x' + digest.slice(-40));
}

const PRICE = ethers.parseEther("0.01");
const STAKE = PRICE * 1000n / 10000n; // 10%

describe("BlackBoxBazaar", function () {
  let seller, buyer, other;
  let targetPriv, targetAddr, targetSigner;

  beforeEach(async function () {
    [seller, buyer, other] = await ethers.getSigners();
    targetPriv = '0x' + BigInt(ethers.hexlify(ethers.randomBytes(32))).toString(16).padStart(64, '0');
    targetAddr = addressFromPriv(targetPriv);
    // The buyer-eligibility check requires msg.sender to actually BE the
    // target account (or its authorized delegate) -- so tests need a real,
    // funded signer for the synthetic target key, not just its address.
    targetSigner = new ethers.Wallet(targetPriv, ethers.provider);
    await other.sendTransaction({ to: targetAddr, value: ethers.parseEther("2") });
  });

  async function deploy() {
    const Bazaar = await ethers.getContractFactory("BlackBoxBazaar");
    const bazaar = await Bazaar.deploy();
    await bazaar.waitForDeployment();
    return bazaar;
  }

  async function createListing(bazaar, commitmentHash) {
    const tx = await bazaar.connect(seller).createListing(
      targetAddr, PRICE, "ECDSA Nonce Reuse", "Critical", "Test Wallet", commitmentHash,
      { value: STAKE }
    );
    await tx.wait();
  }

  it("pays the seller and discloses the finding on a genuine nonce-reuse reveal", async function () {
    const bazaar = await deploy();
    const findingText = "Nonce reuse confirmed between tx A and tx B.";
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes(findingText));
    await createListing(bazaar, commitmentHash);

    await bazaar.connect(targetSigner).purchase(0, { value: PRICE });

    const h1 = ethers.keccak256(ethers.toUtf8Bytes("message one"));
    const h2 = ethers.keccak256(ethers.toUtf8Bytes("message two"));
    const k = ethers.hexlify(ethers.randomBytes(32));
    const sig1 = rawSign(targetPriv, h1, k);
    const sig2 = rawSign(targetPriv, h2, k);
    expect(sig1.r).to.equal(sig2.r); // same nonce -> same r, the crux of the bug

    const sellerBalanceBefore = await ethers.provider.getBalance(seller.address);
    const tx = await bazaar.connect(seller).reveal(
      0, findingText, h1, sig1.v, sig1.r, sig1.s, h2, sig2.v, sig2.s
    );
    const receipt = await tx.wait();
    const gasSpent = receipt.gasUsed * receipt.gasPrice;
    const sellerBalanceAfter = await ethers.provider.getBalance(seller.address);

    expect(sellerBalanceAfter).to.equal(sellerBalanceBefore + PRICE + STAKE - gasSpent);

    const listing = await bazaar.getListing(0);
    expect(listing.status).to.equal(2); // Verified
    expect(listing.finding).to.equal(findingText);

    const repBps = await bazaar.reputationScoreBps(seller.address);
    expect(repBps).to.equal(10000n);
  });

  it("refunds the buyer and slashes the stake when signatures don't recover to the target", async function () {
    const bazaar = await deploy();
    const findingText = "Fake finding.";
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes(findingText));
    await createListing(bazaar, commitmentHash);
    await bazaar.connect(targetSigner).purchase(0, { value: PRICE });

    // Sign with an unrelated key -- does NOT prove control of targetAddr.
    const impostorPriv = '0x' + BigInt(ethers.hexlify(ethers.randomBytes(32))).toString(16).padStart(64, '0');
    const h1 = ethers.keccak256(ethers.toUtf8Bytes("message one"));
    const h2 = ethers.keccak256(ethers.toUtf8Bytes("message two"));
    const k = ethers.hexlify(ethers.randomBytes(32));
    const sig1 = rawSign(impostorPriv, h1, k);
    const sig2 = rawSign(impostorPriv, h2, k);

    const buyerBalanceBefore = await ethers.provider.getBalance(targetAddr);
    const tx = await bazaar.connect(seller).reveal(0, findingText, h1, sig1.v, sig1.r, sig1.s, h2, sig2.v, sig2.s);
    await tx.wait();
    const buyerBalanceAfter = await ethers.provider.getBalance(targetAddr);

    expect(buyerBalanceAfter).to.equal(buyerBalanceBefore + PRICE + STAKE);

    const listing = await bazaar.getListing(0);
    expect(listing.status).to.equal(3); // Failed
    expect(listing.finding).to.equal(""); // never disclosed

    const repBps = await bazaar.reputationScoreBps(seller.address);
    expect(repBps).to.equal(0n);
  });

  it("rejects a reveal whose finding text doesn't match the commitment", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("the real finding"));
    await createListing(bazaar, commitmentHash);
    await bazaar.connect(targetSigner).purchase(0, { value: PRICE });

    const h1 = ethers.keccak256(ethers.toUtf8Bytes("message one"));
    const h2 = ethers.keccak256(ethers.toUtf8Bytes("message two"));
    const k = ethers.hexlify(ethers.randomBytes(32));
    const sig1 = rawSign(targetPriv, h1, k);
    const sig2 = rawSign(targetPriv, h2, k);

    // Even with perfectly valid crypto evidence, a mismatched finding text
    // must fail -- the commitment proves what was promised, not the claim.
    await bazaar.connect(seller).reveal(0, "a different finding entirely", h1, sig1.v, sig1.r, sig1.s, h2, sig2.v, sig2.s);
    const listing = await bazaar.getListing(0);
    expect(listing.status).to.equal(3); // Failed
  });

  it("lets anyone claim a timeout if the seller never reveals", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);
    await bazaar.connect(targetSigner).purchase(0, { value: PRICE });

    await time.increase(3600 + 1);

    const buyerBalanceBefore = await ethers.provider.getBalance(targetAddr);
    await bazaar.connect(other).claimTimeout(0);
    const buyerBalanceAfter = await ethers.provider.getBalance(targetAddr);
    expect(buyerBalanceAfter).to.equal(buyerBalanceBefore + PRICE + STAKE);
  });

  it("refunds the seller's stake when cancelling an unpurchased listing", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);

    const sellerBalanceBefore = await ethers.provider.getBalance(seller.address);
    const tx = await bazaar.connect(seller).cancelListing(0);
    const receipt = await tx.wait();
    const gasSpent = receipt.gasUsed * receipt.gasPrice;
    const sellerBalanceAfter = await ethers.provider.getBalance(seller.address);

    expect(sellerBalanceAfter).to.equal(sellerBalanceBefore + STAKE - gasSpent);
  });

  it("rejects a purchase that doesn't send the exact price", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);
    await expect(
      bazaar.connect(targetSigner).purchase(0, { value: PRICE - 1n })
    ).to.be.revertedWith("wrong price");
  });

  it("rejects a purchase from an address that is neither the target nor an authorized delegate", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);
    // `buyer` here is just a random Hardhat account with no relationship to
    // targetAddr and no authorization -- this is exactly the "buying
    // leverage against someone else's wallet" case the restriction exists
    // to block.
    await expect(
      bazaar.connect(buyer).purchase(0, { value: PRICE })
    ).to.be.revertedWith("only the target account or its authorized delegate may purchase");
  });

  it("rejects the seller buying their own listing", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);
    await expect(
      bazaar.connect(seller).purchase(0, { value: PRICE })
    ).to.be.revertedWith("seller cannot buy own listing");
  });

  it("lets the target account authorize a delegate wallet to purchase on its behalf", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);

    // `buyer` isn't eligible yet...
    await expect(
      bazaar.connect(buyer).purchase(0, { value: PRICE })
    ).to.be.revertedWith("only the target account or its authorized delegate may purchase");

    // ...until the target account explicitly authorizes it (e.g. an ops
    // wallet, so the target never has to transact from the key the finding
    // claims is compromised).
    expect(await bazaar.isEligibleBuyer(0, buyer.address)).to.equal(false);
    await bazaar.connect(targetSigner).authorizeBuyer(buyer.address);
    expect(await bazaar.isEligibleBuyer(0, buyer.address)).to.equal(true);

    await bazaar.connect(buyer).purchase(0, { value: PRICE });
    const listing = await bazaar.getListing(0);
    expect(listing.status).to.equal(1); // Escrowed
    expect(listing.buyer).to.equal(buyer.address);
  });

  it("stops a revoked delegate from purchasing", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);

    await bazaar.connect(targetSigner).authorizeBuyer(buyer.address);
    await bazaar.connect(targetSigner).revokeBuyer(buyer.address);

    await expect(
      bazaar.connect(buyer).purchase(0, { value: PRICE })
    ).to.be.revertedWith("only the target account or its authorized delegate may purchase");
  });

  // --- Regression tests for the "not eligible / execution reverted" bug ---
  // The actual root cause of that bug was never the Solidity logic (it was
  // always the simple `who == target || authorizedBuyer[...]` check below)
  // -- it was the frontend being pointed at a STALE deployment that didn't
  // have isEligibleBuyer() in its bytecode at all, so every call reverted
  // with no data and looked exactly like a logic failure. These tests exist
  // to pin down the exact behavior that must hold on any real deployment,
  // so a future stale-address mixup surfaces immediately as a mismatch
  // against these expectations instead of a confusing on-chain revert.
  it("isEligibleBuyer never reverts, even for a listing id that doesn't exist yet", async function () {
    const bazaar = await deploy();
    // This is exactly the call the deploy script's self-check makes, and
    // exactly the call the frontend makes on every card render. It must
    // return false, not revert -- a revert here is the fingerprint of
    // pointing at a deployment that's missing this function entirely.
    // NOTE: we deliberately do NOT check isEligibleBuyer(0, ethers.ZeroAddress)
    // here. A nonexistent listing's `target` defaults to address(0), so asking
    // "is the zero address eligible" trivially returns true (zero == zero) --
    // that's not a real bypass (no one can ever transact as address(0)), it's
    // just a degenerate case of checking with the same sentinel value the
    // struct defaults to. Using a real, unrelated address is the actual test.
    await expect(bazaar.isEligibleBuyer(0, buyer.address)).to.not.be.reverted;
    expect(await bazaar.isEligibleBuyer(0, buyer.address)).to.equal(false);
    expect(await bazaar.isEligibleBuyer(999, buyer.address)).to.equal(false);
  });

  it("isEligibleBuyer is true for the exact target address the instant a listing is created -- no purchase needed", async function () {
    const bazaar = await deploy();
    const commitmentHash = ethers.keccak256(ethers.toUtf8Bytes("finding"));
    await createListing(bazaar, commitmentHash);
    // This is the exact scenario that looked broken: connect as the wallet
    // that IS the listing's target and check eligibility with nothing else
    // having happened yet. Must be true immediately, straight off `who ==
    // target`, with no authorization step and no prior purchase required.
    expect(await bazaar.isEligibleBuyer(0, targetAddr)).to.equal(true);
    // A different, unrelated address must still be false.
    expect(await bazaar.isEligibleBuyer(0, buyer.address)).to.equal(false);
  });

  it("exposes the full expected public interface (guards against a partial/mismatched deployment)", async function () {
    const bazaar = await deploy();
    // Sanity-checks that every function the frontend depends on is actually
    // present and callable on a fresh deployment of the CURRENT contract
    // source -- if someone edits the contract and forgets to update the
    // frontend/deploy script accordingly, this is the test that should
    // catch the mismatch, not a confused user clicking "Buy".
    expect(typeof bazaar.isEligibleBuyer).to.equal("function");
    expect(typeof bazaar.authorizeBuyer).to.equal("function");
    expect(typeof bazaar.revokeBuyer).to.equal("function");
    expect(typeof bazaar.purchase).to.equal("function");
    expect(typeof bazaar.reveal).to.equal("function");
    expect(typeof bazaar.getListing).to.equal("function");
    expect(await bazaar.listingCount()).to.equal(0n);
  });
});
