// Range-proof gates: round-trips, tampering, soundness edge cases, instrumentation
// self-check (guards the tauX and P-reconstruction bugs), and serialization size.
const { test } = require('node:test');
const assert = require('node:assert');
const BN = require('bn.js');

const bn128 = require('../src/crypto/bn128.js');
const params = require('../src/crypto/params.js');
const bulletproofs = require('../src/crypto/bulletproofs.js');

const ONE = () => new BN(1).toRed(bn128.q);

const makeCommitment = (v, r) => params.g.mul(v).add(params.h.mul(r));

const randomValue = () => new BN(globalThis.crypto.getRandomValues(new Uint32Array(1))[0]);

// Points and red BNs are immutable (ops return new instances), so shallow copies
// give an independent proof clone safe for tampering.
const cloneProof = (proof) => ({
  BA: proof.BA,
  BS: proof.BS,
  T1: proof.T1,
  T2: proof.T2,
  tHat: proof.tHat,
  tauX: proof.tauX,
  mu: proof.mu,
  ip: {
    L: proof.ip.L.slice(),
    R: proof.ip.R.slice(),
    a: proof.ip.a,
    b: proof.ip.b,
  },
});

test('prove -> verify true for edge and random values < 2^32', () => {
  const values = [new BN(0), new BN(1), new BN(2), new BN(1).shln(31), new BN(1).shln(32).subn(1)];
  for (let i = 0; i < 50; i++) values.push(randomValue());
  for (const v of values) {
    const r = bn128.randomScalar();
    const V = makeCommitment(v, r);
    const p = bulletproofs.proveRange(v, r, 32);
    assert.ok(bulletproofs.verifyRange(V, p, 32), 'verifyRange failed for v=' + v.toString(10));
  }
});

test('tampering any component makes verifyRange return false', () => {
  const v = new BN('123456789');
  const r = bn128.randomScalar();
  const V = makeCommitment(v, r);
  const p = bulletproofs.proveRange(v, r, 32);
  assert.ok(bulletproofs.verifyRange(V, p, 32), 'sanity: original proof verifies');

  const cases = [];
  for (const k of ['BA', 'BS', 'T1', 'T2']) {
    const c = cloneProof(p);
    c[k] = c[k].add(params.g); // valid curve point, different value
    cases.push([`tampered ${k}`, c]);
  }
  for (const k of ['tHat', 'tauX', 'mu']) {
    const c = cloneProof(p);
    c[k] = c[k].redAdd(ONE());
    cases.push([`tampered ${k}`, c]);
  }
  p.ip.L.forEach((_, i) => {
    const c = cloneProof(p);
    c.ip.L[i] = c.ip.L[i].add(params.g);
    cases.push([`tampered ip.L[${i}]`, c]);
  });
  p.ip.R.forEach((_, i) => {
    const c = cloneProof(p);
    c.ip.R[i] = c.ip.R[i].add(params.g);
    cases.push([`tampered ip.R[${i}]`, c]);
  });

  for (const [name, c] of cases) {
    assert.ok(!bulletproofs.verifyRange(V, c, 32), `${name} should fail verification`);
  }
});

test('wrong commitment (V of a different value) fails', () => {
  const v = new BN('42');
  const r = bn128.randomScalar();
  const V = makeCommitment(v, r);
  const p = bulletproofs.proveRange(v, r, 32);
  const Vwrong = makeCommitment(new BN('43'), bn128.randomScalar());
  assert.ok(!bulletproofs.verifyRange(Vwrong, p, 32));
});

test('out-of-range v = 2^32 and v = -1 (mod q): proveRange must not throw, verifyRange false', () => {
  // 2^32 (one past the top of the 32-bit range)
  const r1 = bn128.randomScalar();
  const vBig = new BN(1).shln(32);
  let pBig;
  assert.doesNotThrow(() => { pBig = bulletproofs.proveRange(vBig, r1, 32); });
  assert.ok(!bulletproofs.verifyRange(makeCommitment(vBig, r1), pBig, 32));

  // -1 mod q
  const r2 = bn128.randomScalar();
  const vNeg = new BN(1).toRed(bn128.q).redNeg();
  let pNeg;
  assert.doesNotThrow(() => { pNeg = bulletproofs.proveRange(vNeg, r2, 32); });
  assert.ok(!bulletproofs.verifyRange(makeCommitment(vNeg, r2), pNeg, 32));
});

test('n = 16 round-trip; verifying a 32-bit proof with n = 16 fails', () => {
  const v = new BN(1).shln(16).subn(1); // 65535, max 16-bit value
  const r = bn128.randomScalar();
  const V = makeCommitment(v, r);
  const p16 = bulletproofs.proveRange(v, r, 16);
  assert.ok(bulletproofs.verifyRange(V, p16, 16));

  const p32 = bulletproofs.proveRange(new BN('1000000'), bn128.randomScalar(), 32);
  assert.ok(!bulletproofs.verifyRange(makeCommitment(new BN('1000000'), bn128.randomScalar()), p32, 16));
});

test('instrumentation self-check: prover/verifier agree (guards tauX & P-reconstruction)', () => {
  const v = new BN('987654321');
  const r = bn128.randomScalar();
  const V = makeCommitment(v, r);
  const p = bulletproofs.proveRange(v, r, 32);
  const d = bulletproofs._debugVerify(V, p, 32);

  // Challenges recomputed identically.
  assert.ok(p._debug.y.eq(d.y), 'y matches');
  assert.ok(p._debug.z.eq(d.z), 'z matches');
  assert.ok(p._debug.x.eq(d.x), 'x matches');
  assert.ok(p._debug.o.eq(d.o), 'o matches');

  // delta and both sides of the main equation agree between prover and verifier.
  assert.ok(p._debug.delta.eq(d.delta), 'delta matches');
  assert.ok(p._debug.lhs.eq(d.lhs), 'lhs matches');
  assert.ok(p._debug.rhs.eq(d.rhs), 'rhs matches');

  // Main verification equation must hold from the prover's own numbers.
  assert.ok(p._debug.lhs.eq(p._debug.rhs), 'prover main equation holds (tauX must include z^2 * r)');
  // ... and from the verifier's recomputation.
  assert.ok(d.lhs.eq(d.rhs), 'verifier main equation holds');

  // t0 self-consistency: tHat = t0 + t1*x + t2*x^2.
  const { t0, t1, t2, x, tHat } = p._debug;
  assert.ok(t0.redAdd(t1.redMul(x)).redAdd(t2.redMul(x.redSqr())).eq(tHat), 'tHat = t0 + t1 x + t2 x^2');

  // The verifier's reconstructed P must be a valid IPA statement (verifyRange true).
  assert.ok(bulletproofs.verifyRange(V, p, 32), 'end-to-end verify');
});

test('serialization round-trips and re-verifies; proof < 2 KB', () => {
  const v = new BN('123456789');
  const r = bn128.randomScalar();
  const V = makeCommitment(v, r);
  const p = bulletproofs.proveRange(v, r, 32);

  const json = bulletproofs.proofToJSON(p);
  const p2 = bulletproofs.proofFromJSON(json);
  assert.ok(bulletproofs.verifyRange(V, p2, 32), 'JSON round-trip re-verifies');

  const hex = bulletproofs.serializeProofHex(p);
  const proofBytes = (hex.length - 2) / 2;
  // eslint-disable-next-line no-console
  console.log(`serialized proof: ${proofBytes} bytes (hex length ${hex.length}); JSON length ${JSON.stringify(json).length}`);
  assert.ok(hex.length < 2 * 2048, 'proof must be smaller than 2 KB');
});

test('aggregated prove -> verify true for m ∈ {1,2,4,8}', () => {
  for (const m of [1, 2, 4, 8]) {
    for (const n of [16, 32]) {
      const values = [];
      const blindings = [];
      const Vpoints = [];
      for (let j = 0; j < m; j++) {
        const v = randomValue().umod(new BN(1).shln(n).subn(1)).toRed(bn128.q);
        const r = bn128.randomScalar();
        values.push(v);
        blindings.push(r);
        Vpoints.push(makeCommitment(v, r));
      }
      const proof = bulletproofs.proveRangeAggregated(values, blindings, n);
      assert.ok(bulletproofs.verifyRangeAggregated(Vpoints, proof, n),
        `aggregated proof (m=${m}, n=${n}) should verify`);
    }
  }
});

test('aggregated proof tampering fails', () => {
  const n = 16;
  const v1 = new BN(12345).toRed(bn128.q);
  const v2 = new BN(60000).toRed(bn128.q);
  const r1 = bn128.randomScalar();
  const r2 = bn128.randomScalar();
  const V1 = makeCommitment(v1, r1);
  const V2 = makeCommitment(v2, r2);

  const proof = bulletproofs.proveRangeAggregated([v1, v2], [r1, r2], n);

  // Wrong commitment (V2 opened to a different value) must fail.
  const V2wrong = makeCommitment(new BN(999).toRed(bn128.q), r2);
  assert.ok(!bulletproofs.verifyRangeAggregated([V1, V2wrong], proof, n),
    'tampered commitment must fail');

  // Out-of-range value must fail (aggregated relation is v ∈ [0, 2^n)).
  const vBad = new BN(1).shln(n).toRed(bn128.q); // 2^n, out of range
  const rBad = bn128.randomScalar();
  const VBad = makeCommitment(vBad, rBad);
  const badProof = bulletproofs.proveRangeAggregated([v1, vBad], [r1, rBad], n);
  assert.ok(!bulletproofs.verifyRangeAggregated([V1, VBad], badProof, n),
    'out-of-range value must fail');
});

test('aggregated proof size grows O(log m), not O(m)', () => {
  const n = 16;
  const sizes = [];
  for (const m of [1, 2, 4, 8, 16, 32]) {
    const values = [];
    const blindings = [];
    for (let j = 0; j < m; j++) {
      const v = new BN(1000 + j * 1234).toRed(bn128.q);
      const r = bn128.randomScalar();
      values.push(v);
      blindings.push(r);
    }
    const proof = bulletproofs.proveRangeAggregated(values, blindings, n);
    sizes.push((bulletproofs.serializeProofHex(proof).length - 2) / 2);
  }
  // Single proof (m=1) is ~928 B; aggregated m=32 is ~1568 B (not 32×928).
  assert.ok(sizes[sizes.length - 1] < 32 * 928,
    `aggregated m=32 should be far smaller than 32 single proofs (got ${sizes[sizes.length - 1]} vs ${32 * 928})`);
});
