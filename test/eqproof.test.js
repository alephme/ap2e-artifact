// 相等承诺证明测试：完备性 / soundness 反例 / 上下文绑定 / 批量验证 / 序列化
const test = require('node:test');
const assert = require('node:assert');
const BN = require('bn.js');
const bn128 = require('../src/crypto/bn128');
const eq = require('../src/crypto/eqproof');
const { randomCommit } = require('../src/shopping/commitments');

function mkSet(n, sameValue) {
  return Array.from({ length: n }, (_, i) =>
    randomCommit(sameValue ? 100 : 100 + i));
}

function proveAll(rcs, groupId = 1) {
  const out = [];
  for (let i = 1; i < rcs.length; i++) {
    const ctx = { groupId, aId: 0, iId: i };
    out.push({ ctx, Ba: rcs[0].point, Bi: rcs[i].point, proof: eq.proveEq(rcs[0].point, rcs[i].point, rcs[0].randomness, rcs[i].randomness, ctx) });
  }
  return out;
}

test('完备性：相同值，n-1 个证明全部通过', () => {
  for (const n of [2, 4, 8]) {
    const rcs = mkSet(n, true);
    const proofs = proveAll(rcs);
    assert.strictEqual(proofs.length, n - 1);
    for (const p of proofs) assert.ok(eq.verifyEq(p.Ba, p.Bi, p.proof, p.ctx));
  }
});

test('soundness：值不同必须被拒', () => {
  const rcs = mkSet(4, false); // 每个商家不同值
  const proofs = proveAll(rcs);
  for (const p of proofs) assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, p.proof, p.ctx), false);
});

test('篡改 s / T 必须被拒', () => {
  const rcs = mkSet(3, true);
  const p = proveAll(rcs)[0];
  const one = new BN(1).toRed(bn128.q);
  assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, { T: p.proof.T, s: p.proof.s.redAdd(one) }, p.ctx), false);
  assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, { T: p.proof.T.add(bn128.curve.g), s: p.proof.s }, p.ctx), false);
});

test('上下文绑定：换组 / 换商家 id 必须被拒', () => {
  const rcs = mkSet(4, true);
  const p = proveAll(rcs)[0];
  assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, p.proof, { ...p.ctx, groupId: 99 }), false);
  assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, p.proof, { ...p.ctx, iId: 3 }), false);
  assert.strictEqual(eq.verifyEq(p.Ba, p.Bi, p.proof, { ...p.ctx, aId: 1 }), false);
});

test('批量验证：全真通过，掺假被拒', () => {
  const rcs = mkSet(8, true);
  const proofs = proveAll(rcs);
  assert.ok(eq.batchVerifyEq(proofs));
  // 掺一个假（值不同）
  const badRcs = mkSet(8, false);
  const badProofs = proveAll(badRcs);
  const mixed = [...proofs];
  mixed[0] = badProofs[0];
  assert.strictEqual(eq.batchVerifyEq(mixed), false);
});

test('序列化往返', () => {
  const rcs = mkSet(3, true);
  const p = proveAll(rcs)[0];
  const json = eq.eqProofToJSON(p.proof);
  assert.ok(eq.verifyEq(p.Ba, p.Bi, eq.eqProofFromJSON(json), p.ctx));
});

test('证明大小：T(64B) + s(32B) = 96B（BN128 未压缩表示）', () => {
  const rcs = mkSet(2, true);
  const p = proveAll(rcs)[0];
  const json = eq.eqProofToJSON(p.proof);
  const bytes = (json.T.length - 2) / 2 + (json.s.length - 2) / 2;
  assert.strictEqual(bytes, 96);
});
