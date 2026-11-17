// Global parameters for the original-Bulletproofs range proof (Bünz et al. 2018).
// The generators are derived identically to the Solidity verifiers:
//   - g  = mapInto(sha3("G"))   (== curve generator, matches Utils.g())
//   - h  = mapInto(sha3("H"))   (matches Utils.h())
//   - gs[i] = mapInto(sha3("G", i))  (matches InnerProductVerifier.gs(i))
//   - hs[i] = mapInto(sha3("H", i))  (matches InnerProductVerifier.hs(i))
//   - gSum = Σ gs[i]            (matches BurnVerifier.gSum())
// 生成元种子用自包含的 soliditySha3Packed（与 web3 soliditySha3 字节等价，
// 由 test/compat.test.js 守护），运行时无需 web3 依赖。
const bn128 = require('./bn128.js');
const utils = require('./utils.js');
const { PointVector } = require('./algebra.js');
const { soliditySha3Packed } = require('./keccak.js');

const N = 32; // default range bit-length

const g = utils.mapInto(soliditySha3Packed("G")); // also equals curve generator
const h = utils.mapInto(soliditySha3Packed("H"));
const gs = new PointVector(Array.from({ length: N }).map((_, i) => utils.mapInto(soliditySha3Packed("G", i))));
const hs = new PointVector(Array.from({ length: N }).map((_, i) => utils.mapInto(soliditySha3Packed("H", i))));
const gSum = gs.sum();

// Lazy generator expansion for aggregated range proofs, which need m·n-dimension
// generator vectors (m values aggregated into one proof). mapInto is deterministic,
// so extending the cache to index i simply derives gs[i] = mapInto("G", i).
const _gsCache = gs.getVector().slice();
const _hsCache = hs.getVector().slice();

function getGs(dim) {
    while (_gsCache.length < dim) {
        _gsCache.push(utils.mapInto(soliditySha3Packed("G", _gsCache.length)));
    }
    return new PointVector(_gsCache.slice(0, dim));
}

function getHs(dim) {
    while (_hsCache.length < dim) {
        _hsCache.push(utils.mapInto(soliditySha3Packed("H", _hsCache.length)));
    }
    return new PointVector(_hsCache.slice(0, dim));
}

module.exports = { N, g, h, gs, hs, gSum, getGs, getHs };
