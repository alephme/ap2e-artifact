// 相等承诺证明（Schnorr + Fiat–Shamir）：
// 证明 B_i 与 B_a 承诺同一个值，即 B_i · B_a^{-1} = h^{Δr} 且证明者知道 Δr = r_i − r_a。
// 纯 JS 实现，曲线自动跟随 ZKP_CURVE；与 rangeproof 后端（JS/C）无关。
//
// 安全性：若 x_i ≠ x_a，则 B_i·B_a^{-1} = g^{x_i−x_a}·h^{Δr}，伪造 Schnorr 需要知道
// log_h(g^{x_i−x_a})，而 g,h 是独立 NUMS 生成元（mapInto(sha3)），故不可能。
const BN = require('bn.js');
const bn128 = require('./bn128.js');
const params = require('./params.js');
const utils = require('./utils.js');
const { PointVector, FieldVector } = require('./algebra.js');

// 域分隔 token（"EQ"），编码为固定 32 字节以避免拼接歧义。
const DOMAIN = new BN('4551', 16);

// h 是固定基点：预计算倍数表，使 h.mul 走固定基 NAF（~1.3× 加速，一次性开销）。
// 只加速、不改语义，对共享 params.h 的其他使用方安全。
if (typeof params.h.precompute === 'function') params.h.precompute(8);

// ctx: { groupId, aId, iId } — 三个都是整数（组编号 / 基准商家 id / 目标商家 id）。
// 绑定它们可防跨组、跨商家重放。
function ctxHex(ctx, Ba, Bi, T) {
  const c = ctx || {};
  return '0x' +
    bn128.bytes(DOMAIN).slice(2) +
    bn128.bytes(new BN(c.groupId || 0)).slice(2) +
    bn128.bytes(new BN(c.aId || 0)).slice(2) +
    bn128.bytes(new BN(c.iId || 0)).slice(2) +
    bn128.representation(Ba).slice(2) +
    bn128.representation(Bi).slice(2) +
    bn128.representation(T).slice(2);
}

function challenge(ctx, Ba, Bi, T) {
  return utils.hash(ctxHex(ctx, Ba, Bi, T));
}

// 生成证明。Ba/Bi: 承诺点；ra/ri: 对应盲因子（red BN）。
function proveEq(Ba, Bi, ra, ri, ctx) {
  const delta = ri.redSub(ra);            // Δr = r_i − r_a
  const k = bn128.randomScalar();
  const T = params.h.mul(k);
  const c = challenge(ctx, Ba, Bi, T);
  const s = k.redAdd(c.redMul(delta));    // s = k + c·Δr
  return { T, s };
}

// 验证：h^s == T · (B_i · B_a^{-1})^c
function verifyEq(Ba, Bi, proof, ctx) {
  const c = challenge(ctx, Ba, Bi, proof.T);
  const diff = Bi.add(Ba.neg());
  return params.h.mul(proof.s).eq(proof.T.add(diff.mul(c)));
}

// 批量验证：逐条验证（每证明 2 次点乘：h^{s} 与 Δ^{c}；T 只做点加）。
// 注：Schnorr 的"随机 α 合并"在 JS + elliptic 下反而更慢——它把 T 也变成点乘
// （1+2m 次 mul），而逐条验证只需 2m 次 mul，故此处直接循环。
// entries: [{ Ba, Bi, proof, ctx }]
function batchVerifyEq(entries, ctx) {
  for (const e of entries) {
    if (!verifyEq(e.Ba, e.Bi, e.proof, e.ctx || ctx)) return false;
  }
  return true;
}

// 序列化：{ T: "0x" + x(64) + y(64), s: "0x" + 64hex }
function eqProofToJSON(proof) {
  return { T: bn128.representation(proof.T), s: bn128.bytes(proof.s) };
}

function eqProofFromJSON(json) {
  const body = json.T.slice(2);
  return {
    T: bn128.curve.point(body.slice(0, 64), body.slice(64)),
    s: new BN(json.s.slice(2), 16).toRed(bn128.q),
  };
}

module.exports = { proveEq, verifyEq, batchVerifyEq, eqProofToJSON, eqProofFromJSON };
