// C 后端（真 Bulletproofs）JS 封装：koffi → bp_wrapper.dll → libsecp256k1_bp.dll
const koffi = require('koffi');
const path = require('path');

const lib = koffi.load(path.join(__dirname, 'lib', 'bp_wrapper.dll'));
const bpInit   = lib.func('int bp_init(size_t nbits)');
const bpCommit = lib.func('int bp_commit(const unsigned char *blind, uint64 value, unsigned char *commit_out)');
const bpProve  = lib.func('int bp_prove(unsigned char *proof, size_t *plen, uint64 value, const unsigned char *blind, size_t nbits)');
const bpVerify = lib.func('int bp_verify(const unsigned char *proof, size_t plen, const unsigned char *commit, size_t nbits)');
const bpGenV   = lib.func('int bp_generator_value(unsigned char *out33)');
const bpGenB   = lib.func('int bp_generator_blind(unsigned char *out33)');

const bpCommitSum = lib.func('int bp_commit_sum(const unsigned char *commits_in, size_t n, size_t npos, unsigned char *out33)');
const bpBlindSum  = lib.func('int bp_blind_sum_flat(unsigned char *blind_out, const unsigned char *blinds_flat, size_t n, size_t npos)');

const MAX_PROOF = 1319;
let initNbits = 0;

function init(nbits = 32) {
  if (initNbits !== nbits) { bpInit(nbits); initNbits = nbits; }
  return true;
}

// 生成元（33B 压缩序列化）
function generators() {
  init();
  const value = Buffer.alloc(33), blind = Buffer.alloc(33);
  if (!bpGenV(value) || !bpGenB(blind)) throw new Error('generator export failed');
  return { value, blind };
}

// Pedersen 承诺：blind(32B) + value → 33B 承诺
function commit(blind, value, nbits = 32) {
  init(nbits);
  const out = Buffer.alloc(33);
  if (!bpCommit(blind, value, out)) throw new Error('commit failed (blind >= group order?)');
  return out;
}

// 承诺求和/差：commits 为 33B Buffer 数组，前 npos 个为正其余为负 → 33B
function commitSum(commits, npos) {
  init();
  if (npos > commits.length) throw new Error('npos > n');
  const flat = Buffer.concat(commits);
  const out = Buffer.alloc(33);
  if (!bpCommitSum(flat, commits.length, npos, out)) throw new Error('commit_sum failed');
  return out;
}

// 盲因子求和/差：blinds 为 32B Buffer 数组，前 npos 个为正其余为负 → 32B
function blindSum(blinds, npos) {
  init();
  const flat = Buffer.concat(blinds);
  const out = Buffer.alloc(32);
  if (!bpBlindSum(out, flat, blinds.length, npos)) throw new Error('blind_sum failed');
  return out;
}

// 范围证明：value + blind → { proof, plen }
function prove(value, blind, nbits = 32) {
  init(nbits);
  const proof = Buffer.alloc(MAX_PROOF);
  const plen = Buffer.alloc(8); plen.writeUInt32LE(MAX_PROOF, 0);
  if (!bpProve(proof, plen, value, blind, nbits)) throw new Error('prove failed');
  const len = plen.readUInt32LE(0);
  return { proof: proof.slice(0, len), plen: len };
}

// 验证：proof + 33B 承诺 → bool（承诺值在 [0, 2^nbits) 内）
function verify(proof, commit33, nbits = 32) {
  init(nbits);
  return bpVerify(proof, proof.length, commit33, nbits) === 1;
}

module.exports = { init, generators, commit, commitSum, blindSum, prove, verify, MAX_PROOF };
