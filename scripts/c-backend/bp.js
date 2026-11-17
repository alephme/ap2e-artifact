// JS 调用真 Bulletproofs（C）：通过 koffi → bp_wrapper.dll → libsecp256k1_bp.dll
// 用法: node scripts/c-backend/bp.js
const koffi = require('koffi');
const crypto = require('crypto');
const path = require('path');

const lib = koffi.load(path.join(__dirname, 'lib', 'bp_wrapper.dll'));
const bpInit   = lib.func('int bp_init(size_t nbits)');
const bpCommit = lib.func('int bp_commit(const unsigned char *blind, uint64 value, unsigned char *commit_out)');
const bpProve  = lib.func('int bp_prove(unsigned char *proof, size_t *plen, uint64 value, const unsigned char *blind, size_t nbits)');
const bpVerify = lib.func('int bp_verify(const unsigned char *proof, size_t plen, const unsigned char *commit, size_t nbits)');

const NBITS = 32;
const VALUE = parseInt(process.argv[2] || '12345', 10);
const MAX_PROOF = 1319;

console.log('bp_init:', bpInit(NBITS));

const blind = crypto.randomBytes(32);
const commit = Buffer.alloc(33);
console.log('bp_commit:', bpCommit(blind, VALUE, commit), '| commit:', commit.toString('hex').slice(0, 16) + '…');

const proof = Buffer.alloc(MAX_PROOF);
const plenBuf = Buffer.alloc(8); plenBuf.writeUInt32LE(MAX_PROOF, 0);
console.log('bp_prove:', bpProve(proof, plenBuf, VALUE, blind, NBITS), '| 证明大小:', plenBuf.readUInt32LE(0), 'B');
const proofLen = plenBuf.readUInt32LE(0);

console.log('bp_verify:', bpVerify(proof, proofLen, commit, NBITS));

// ---- 性能：20 次 prove/verify ----
const med = (a) => { a.sort((x, y) => x - y); return a[Math.floor(a.length / 2)]; };
const tp = [], tv = [];
for (let i = 0; i < 20; i++) {
  const p = Buffer.alloc(MAX_PROOF); const pl = Buffer.alloc(8); pl.writeUInt32LE(MAX_PROOF, 0);
  const bl = crypto.randomBytes(32);
  const t0 = performance.now();
  bpProve(p, pl, VALUE + i, bl, NBITS);
  tp.push(performance.now() - t0);
}
for (let i = 0; i < 20; i++) {
  const t0 = performance.now();
  bpVerify(proof, proofLen, commit, NBITS);
  tv.push(performance.now() - t0);
}
console.log(`\nC Bulletproofs (n=${NBITS}) 中位数/20次: prove ${med(tp).toFixed(2)} ms  verify ${med(tv).toFixed(2)} ms`);
console.log(`JS 版对照: prove ~650 ms  verify ~323 ms  →  prove 快 ${(650 / med(tp)).toFixed(0)}×, verify 快 ${(323 / med(tv)).toFixed(0)}×`);
console.log(`证明大小: ${proofLen} B（论文 Table 2 的 32-bit 值 = 610 B）`);
