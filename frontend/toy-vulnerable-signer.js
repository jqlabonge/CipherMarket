/**
 * TOY VULNERABLE SIGNER -- DEMO ONLY.
 *
 * This is a tiny, self-contained secp256k1 implementation (no dependencies,
 * so the app needs zero `npm install` to run) used ONLY to *simulate* a
 * buggy wallet/signer that reuses ECDSA nonces -- i.e. to play the role of
 * "the vulnerable target" in this demo, so a seller has a genuine nonce-
 * reuse finding to disclose. Real wallet interaction (connecting MetaMask,
 * sending transactions, calling the deployed contract) is handled entirely
 * by ethers.js, loaded from a CDN in index.html -- this file never touches
 * the user's real wallet or real funds.
 *
 * Ordinary ECDSA signers (MetaMask, ethers, every real wallet) derive the
 * nonce `k` deterministically from the private key AND the message
 * (RFC 6979), specifically so that two different messages never reuse `k`.
 * That's why this file exists: to intentionally reproduce the bug class
 * this whole marketplace is about, for a synthetic demo target only.
 *
 * NEVER use this to sign anything with a real private key.
 */

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n % P;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n % P;
const G = [GX, GY];

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function invMod(a, m) {
  // Fermat's little theorem (m is prime for both P and N here)
  return powMod(mod(a, m), m - 2n, m);
}

function powMod(base, exp, mod_) {
  let result = 1n;
  base = mod(base, mod_);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, mod_);
    exp >>= 1n;
    base = mod(base * base, mod_);
  }
  return result;
}

function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2, P) === 0n) return null;
  let lam;
  if (x1 === x2 && y1 === y2) {
    lam = mod(3n * x1 * x1 * invMod(2n * y1, P), P);
  } else {
    lam = mod((y2 - y1) * invMod(mod(x2 - x1, P), P), P);
  }
  const x3 = mod(lam * lam - x1 - x2, P);
  const y3 = mod(lam * (x1 - x3) - y1, P);
  return [x3, y3];
}

function pointMul(k, pt) {
  let result = null;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

/** Deliberately accepts an explicit nonce `k` -- the whole point of this
 * file. Real signers never let you do this. */
function toySign(privKeyHex, msgHashHex, kHex) {
  const d = BigInt(privKeyHex);
  const h = BigInt(msgHashHex);
  const k = BigInt(kHex);
  const R = pointMul(k, G);
  const r = mod(R[0], N);
  const kInv = invMod(k, N);
  let s = mod(kInv * (h + r * d), N);
  let yParity = Number(mod(R[1], 2n));
  if (s > N / 2n) {
    s = N - s;
    yParity ^= 1;
  }
  const v = 27 + yParity;
  return {
    r: '0x' + r.toString(16).padStart(64, '0'),
    s: '0x' + s.toString(16).padStart(64, '0'),
    v,
  };
}

function toyPrivToAddress(privKeyHex) {
  const d = BigInt(privKeyHex);
  const pub = pointMul(d, G);
  const xHex = pub[0].toString(16).padStart(64, '0');
  const yHex = pub[1].toString(16).padStart(64, '0');
  // keccak256 of the uncompressed pubkey (x||y), last 20 bytes -- delegated
  // to ethers (loaded globally as `ethers` in index.html) for the hashing,
  // since ethers' keccak256 is the real, audited implementation.
  const digest = ethers.keccak256('0x' + xHex + yHex);
  return ethers.getAddress('0x' + digest.slice(-40));
}

function randomPrivKey() {
  const bytes = ethers.randomBytes(32);
  let hex = ethers.hexlify(bytes);
  // Ensure it's a valid scalar < N (astronomically likely already true).
  if (BigInt(hex) === 0n || BigInt(hex) >= N) return randomPrivKey();
  return hex;
}

window.ToySigner = { toySign, toyPrivToAddress, randomPrivKey, N };
