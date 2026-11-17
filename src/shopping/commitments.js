// 承诺工具：Pedersen 承诺、乘性差值承诺、点的十六进制编解码、盲因子打开序列化。
// 符号约定见计划：B_i=卖家报价承诺，W=用户上限承诺，Δ=差值承诺。
const BN = require('bn.js');
const bn128 = require('../crypto/bn128');
const params = require('../crypto/params');

const { g, h } = params;

// 以整数 value 与随机盲因子构造承诺。返回 { value(red), randomness(red), point }。
function randomCommit(valueInt) {
  const value = new BN(valueInt).toRed(bn128.q);
  const randomness = bn128.randomScalar();
  const point = g.mul(value).add(h.mul(randomness));
  return { value, randomness, point };
}

// 由值（red）与盲因子（red）计算承诺点。
function commit(valueRed, randomnessRed) {
  return g.mul(valueRed).add(h.mul(randomnessRed));
}

// 乘性差值：B_a · B_b^{-1}（即点 a 加上 b 的逆元）。
function difference(Ba, Bb) {
  return Ba.add(Bb.neg());
}

// 三点差：B_a · B_b^{-1} · B_c^{-1}（即 a - b - c）。
// 用于不可行证明（p_i - L - 1）：Δ = B_i · W^{-1} · g^{-1}
function subTwo(Ba, Bb, Bc) {
  return Ba.add(Bb.neg()).add(Bc.neg());
}

// G-加权逆差：g^{k} · B_b^{-1}（即 k·g - b）。
// 用于价格有效性 π_max（2^n-1 - p_i）：Δ = g^{2^n-1} · B_i^{-1}
function gWeightedSub(kRed, Bb) {
  return params.g.mul(kRed).add(Bb.neg());
}

// 点 <-> "0x" + x(64hex) + y(64hex)
function pointToHex(point) {
  return bn128.representation(point);
}
function hexToPoint(hex) {
  const body = hex.slice(2); // 去掉 0x，128 字符 = 64 x + 64 y
  return bn128.curve.point(body.slice(0, 64), body.slice(64));
}

// 盲因子打开序列化：密封信封里携带 (value 整数, blinding hex)。
function openingToJson(valueInt, randomnessRed) {
  return JSON.stringify({ value: String(valueInt), blinding: bn128.bytes(randomnessRed) });
}
function parseOpening(str) {
  const { value, blinding } = JSON.parse(str);
  return {
    valueInt: parseInt(value, 10),
    value: new BN(value).toRed(bn128.q),
    randomness: new BN(blinding.slice(2), 16).toRed(bn128.q),
  };
}

module.exports = { randomCommit, commit, difference, subTwo, gWeightedSub, pointToHex, hexToPoint, openingToJson, parseOpening };
