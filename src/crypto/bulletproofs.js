// Original Bulletproofs (Bünz et al. 2018) single range proof (n-bit).
//
// This is NOT a port of zether's fused sigma-protocol BurnProof. It reuses only
// the curve layer, hash-to-curve / Fiat-Shamir helpers, vector algebra, and the
// IPA recursion. The critical difference from zether's burn.js: tauX includes the
// z^2 * r term, which the original-Bulletproofs direct verification equation
// REQUIRES (in zether it lived inside the sigma protocol instead).
const BN = require('bn.js');

const bn128 = require('./bn128.js');
const { abiEncode } = require('./keccak.js');
const utils = require('./utils.js');
const { PedersenCommitment, FieldVector, PointVector } = require('./algebra.js');
const { FieldVectorPolynomial } = require('./misc.js');
const InnerProductProof = require('./innerproduct.js');
const params = require('./params.js');

// ---- shared challenge / vector builders (identical in prover and verifier) ----

const buildYs = (y, n) => {
    const ys = new FieldVector([new BN(1).toRed(bn128.q)]);
    for (let i = 1; i < n; i++) ys.push(ys.getVector()[i - 1].redMul(y));
    return ys;
};

const buildTwos = (n) => new FieldVector(Array.from({ length: n }, (_, i) => new BN(1).shln(i).toRed(bn128.q)));

// ⟨1, 2^n⟩ = 2^n − 1. NOTE: `new BN(2).shln(n)` would be 2^(n+1) (off by one);
// we need `new BN(1).shln(n)`, matching Solidity `1 << n`.
const twoPowNMinusOne = (n) => new BN(1).shln(n).subn(1).toRed(bn128.q);

const hashY = (V, BA, BS) => utils.hash(abiEncode(
    ['bytes32[2]', 'bytes32[2]', 'bytes32[2]'],
    [bn128.serialize(V), bn128.serialize(BA), bn128.serialize(BS)]
));

const hashX = (z, T1, T2) => utils.hash(abiEncode(
    ['bytes32', 'bytes32[2]', 'bytes32[2]'],
    [bn128.bytes(z), bn128.serialize(T1), bn128.serialize(T2)]
));

const hashO = (x, tHat, mu) => utils.hash(abiEncode(
    ['bytes32', 'bytes32', 'bytes32'],
    [bn128.bytes(x), bn128.bytes(tHat), bn128.bytes(mu)]
));

// ---- serialization helpers ----

const redFromHex = (hex) => new BN(hex.slice(2), 16).toRed(bn128.q);

const pointFromRep = (rep) => {
    const hex = rep.slice(2);
    return bn128.deserialize(['0x' + hex.slice(0, 64), '0x' + hex.slice(64)]);
};

// ---- prover ----

// v, r: red BNs (the committed value and its blinding). Returns a plain-JS proof
// object {BA, BS, T1, T2, tHat, tauX, mu, ip} (points as elliptic points) plus a
// `_debug` instrumentation field.
function proveRange(v, r, n) {
    n = n || params.N;

    // Accept either already-reduced BNs (the intended API) or plain BNs.
    // g^v == g^(v mod q), so the commitment point is unchanged either way.
    const vRed = v.red ? v : v.toRed(bn128.q);
    const rRed = r.red ? r : r.toRed(bn128.q);
    v = vRed;
    r = rRed;

    const gsN = params.gs.slice(0, n);
    const hsN = params.hs.slice(0, n);

    // 1. aL = bit extraction of v; aR = aL - 1.
    // NOTE: no v.toString(2, n) — that pads but does not truncate. We want
    // out-of-range values to produce a structurally-valid-but-wrong proof, not a crash.
    const aLVector = [];
    for (let i = 0; i < n; i++) {
        aLVector.push(new BN(v.fromRed().ushrn(i).andln(1)).toRed(bn128.q));
    }
    const aL = new FieldVector(aLVector);
    const aR = aL.plus(new BN(1).toRed(bn128.q).redNeg());

    // 2. blinding scalars and random vectors.
    const alpha = bn128.randomScalar();
    const rho = bn128.randomScalar();
    const sL = new FieldVector(Array.from({ length: n }).map(bn128.randomScalar));
    const sR = new FieldVector(Array.from({ length: n }).map(bn128.randomScalar));

    const BA = params.h.mul(alpha).add(gsN.multiExponentiate(aL)).add(hsN.multiExponentiate(aR));
    const BS = params.h.mul(rho).add(gsN.multiExponentiate(sL)).add(hsN.multiExponentiate(sR));

    // V = g^v · h^r recomputed by the prover.
    const V = params.g.mul(v).add(params.h.mul(r));

    // 3. y challenge.
    const y = hashY(V, BA, BS);
    const ys = buildYs(y, n);

    // 4. z challenge.
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();
    const z3 = z.redMul(z2);

    // 5. twoTimesZs = 2^n * z^2.
    const twoTimesZs = buildTwos(n).times(z2);

    // 6. l(X), r(X).
    const lPoly = new FieldVectorPolynomial(aL.plus(z.redNeg()), sL);
    const rPoly = new FieldVectorPolynomial(ys.hadamard(aR.plus(z)).add(twoTimesZs), ys.hadamard(sR));

    // 7. [t0, t1, t2] = l·r.
    const tPoly = lPoly.innerProduct(rPoly);

    // 8. T1, T2 (keep randomness = tau1, tau2).
    const T1 = PedersenCommitment.commit(tPoly[1]);
    const T2 = PedersenCommitment.commit(tPoly[2]);

    // 9. x challenge.
    const x = hashX(z, T1.point(), T2.point());

    // 10. l(x), r(x), tHat.
    const lEval = lPoly.evaluate(x);
    const rEval = rPoly.evaluate(x);
    const tHat = lEval.innerProduct(rEval);

    // 11. tauX — THE CRITICAL FIX: includes z^2 · r. mu = alpha + x·rho.
    const tauX = T1.randomness.redMul(x).redAdd(T2.randomness.redMul(x.redSqr())).redAdd(z2.redMul(r));
    const mu = alpha.redAdd(rho.redMul(x));

    // 12. o challenge, u = h^o, hsPrime = hs · y^-1.
    const o = hashO(x, tHat, mu);
    const u = params.h.mul(o);
    const hsPrime = hsN.hadamard(ys.invert());

    // 13. P = u^tHat · g^l · (h')^r.
    const P = u.mul(tHat).add(gsN.multiExponentiate(lEval)).add(hsPrime.multiExponentiate(rEval));

    // 14. IPA.
    const ip = InnerProductProof.prove(gsN, hsPrime, u, lEval, rEval, o);

    // ---- instrumentation ----
    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(z3.redMul(twoPowNMinusOne(n)));
    const lhs = params.g.mul(tHat).add(params.h.mul(tauX));
    const rhs = V.mul(z2).add(params.g.mul(delta)).add(T1.point().mul(x)).add(T2.point().mul(x.redSqr()));

    const proof = { BA, BS, T1: T1.point(), T2: T2.point(), tHat, tauX, mu, ip };
    proof._debug = { V, delta, t0: tPoly[0], t1: tPoly[1], t2: tPoly[2], y, z, z2, x, o, tHat, lhs, rhs };
    return proof;
}

// ---- verifier ----

// 逐轮折叠版验证器（对照/回滚用，与 InnerProductProof.verifyFolding 同思路）。
function verifyRangeFolding(Vpoint, proof, n) {
    n = n || params.N;

    const y = hashY(Vpoint, proof.BA, proof.BS);
    const ys = buildYs(y, n);
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();
    const z3 = z.redMul(z2);
    const twoTimesZs = buildTwos(n).times(z2);

    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(z3.redMul(twoPowNMinusOne(n)));

    const x = hashX(z, proof.T1, proof.T2);

    const lhs = params.g.mul(proof.tHat).add(params.h.mul(proof.tauX));
    const rhs = Vpoint.mul(z2).add(params.g.mul(delta)).add(proof.T1.mul(x)).add(proof.T2.mul(x.redSqr()));
    if (!lhs.eq(rhs)) return false;

    const gsN = params.gs.slice(0, n);
    const hsN = params.hs.slice(0, n);
    const hPrimes = hsN.hadamard(ys.invert());
    let hPrimeSum = bn128.zero;
    for (let i = 0; i < n; i++) {
        hPrimeSum = hPrimeSum.add(hPrimes.getVector()[i].mul(ys.getVector()[i].redMul(z).redAdd(twoTimesZs.getVector()[i])));
    }

    const o = hashO(x, proof.tHat, proof.mu);
    const u = params.h.mul(o);
    let P = proof.BA.add(proof.BS.mul(x)).add(gsN.sum().mul(z.redNeg()))
        .add(hPrimeSum).add(params.h.mul(proof.mu.redNeg())).add(u.mul(proof.tHat));

    return InnerProductProof.verifyFolding(gsN, hPrimes, u, P, proof.ip, o);
}

// 合并验证（论文 §6.2）——分解版：返回 { pts, scs }（点/标量数组），不执行 multi-exp。
// 单独验证 verifyRange 与批量验证 batchVerifyRange 共用。
// 把主方程 (98) 与 IPA 检查 (105) 用组合挑战 c 线性合并为单次 multi-exponentiation；
// size = 2n + 2log₂n + 8 次点乘，对比折叠版 ~4n + 2log₂n + 18（省 hPrimes 哈达玛 + hPrimeSum）。
function verifyRangeDecomposed(Vpoint, proof, n) {
    n = n || params.N;
    const logN = Math.log2(n);

    // 挑战（与折叠版完全相同的编码顺序）
    const y = hashY(Vpoint, proof.BA, proof.BS);
    const ys = buildYs(y, n);
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();
    const z3 = z.redMul(z2);
    const twoTimesZs = buildTwos(n).times(z2);
    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(z3.redMul(twoPowNMinusOne(n)));
    const x = hashX(z, proof.T1, proof.T2);
    const o = hashO(x, proof.tHat, proof.mu);
    const u = params.h.mul(o);

    // IPA 各轮挑战 x_j（与 InnerProductProof.verify 相同哈希）
    const xs = [];
    let prev = o;
    for (let j = 0; j < logN; j++) {
        const xj = utils.hash(abiEncode(
            ['bytes32', 'bytes32[2]', 'bytes32[2]'],
            [bn128.bytes(prev), bn128.serialize(proof.ip.L[j]), bn128.serialize(proof.ip.R[j])]
        ));
        xs.push(xj);
        prev = xj;
    }

    // s_i = Π_j x_j^{±1}（g 侧指数），t_i 符号相反（h 侧指数）
    const one = new BN(1).toRed(bn128.q);
    const s = new Array(n).fill(one);
    const t = new Array(n).fill(one);
    for (let j = 0; j < logN; j++) {
        const xj = xs[j];
        const xjInv = xj.redInvm();
        const bit = logN - 1 - j;
        for (let i = 0; i < n; i++) {
            if (((i >> bit) & 1) === 1) { s[i] = s[i].redMul(xj); t[i] = t[i].redMul(xjInv); }
            else { s[i] = s[i].redMul(xjInv); t[i] = t[i].redMul(xj); }
        }
    }

    // 组合挑战 c（确定性：从证明 + V 派生，强 Fiat-Shamir）
    let cSrc = "0x";
    cSrc += bn128.representation(Vpoint).slice(2);
    for (const f of [proof.BA, proof.BS, proof.T1, proof.T2]) cSrc += bn128.representation(f).slice(2);
    for (const f of [proof.tHat, proof.tauX, proof.mu]) cSrc += bn128.bytes(f).slice(2);
    for (let j = 0; j < logN; j++) {
        cSrc += bn128.representation(proof.ip.L[j]).slice(2);
        cSrc += bn128.representation(proof.ip.R[j]).slice(2);
    }
    cSrc += bn128.bytes(proof.ip.a).slice(2);
    cSrc += bn128.bytes(proof.ip.b).slice(2);
    const c = utils.hash(cSrc);

    // 单次 multi-exponentiation == 无穷远点
    const gsN = params.gs.slice(0, n);
    const hsN = params.hs.slice(0, n);
    const gv = gsN.getVector(), hv = hsN.getVector(), yv = ys.getVector(), tv = twoTimesZs.getVector();
    const pts = [];
    const scs = [];
    pts.push(params.g);  scs.push(c.redMul(proof.tHat.redSub(delta)));
    pts.push(params.h);  scs.push(c.redMul(proof.tauX).redAdd(proof.mu));
    pts.push(Vpoint);    scs.push(c.redMul(z2).redNeg());
    pts.push(proof.T1);  scs.push(c.redMul(x).redNeg());
    pts.push(proof.T2);  scs.push(c.redMul(x.redSqr()).redNeg());
    pts.push(u);         scs.push(proof.ip.a.redMul(proof.ip.b).redSub(proof.tHat));
    pts.push(proof.BA);  scs.push(one.redNeg());
    pts.push(proof.BS);  scs.push(x.redNeg());
    for (let i = 0; i < n; i++) {
        pts.push(gv[i]); scs.push(z.redAdd(proof.ip.a.redMul(s[i])));
        const yInv = yv[i].redInvm();
        pts.push(hv[i]); scs.push(z.redAdd(tv[i].redMul(yInv)).redNeg().redAdd(proof.ip.b.redMul(t[i]).redMul(yInv)));
    }
    for (let j = 0; j < logN; j++) {
        const xj2 = xs[j].redSqr();
        pts.push(proof.ip.L[j]); scs.push(xj2.redNeg());
        pts.push(proof.ip.R[j]); scs.push(xj2.redInvm().redNeg());
    }

    return { pts, scs };
}

// 单证明验证：一次 multi-exp == 无穷远点。
function verifyRange(Vpoint, proof, n) {
    const { pts, scs } = verifyRangeDecomposed(Vpoint, proof, n);
    return new PointVector(pts).multiExponentiate(new FieldVector(scs)).isInfinity();
}

// 批量验证（论文 §6.2 Batch verification）：m 个同结构 n 维证明，随机 α_i 线性组合，
// 按点合并公共生成元（g, h, gs, hs 只出现一次），总点乘 = 2n+2 + m·(6+2log₂n)。
// entries: [{ V, proof }, ...]。α_i 从全部输入确定性派生（强 Fiat-Shamir）。
function batchVerifyRange(entries, n) {
    if (entries.length === 0) return true;
    let src = "0x";
    for (const e of entries) {
        src += bn128.representation(e.V).slice(2);
        for (const f of [e.proof.BA, e.proof.BS, e.proof.T1, e.proof.T2]) src += bn128.representation(f).slice(2);
        for (const f of [e.proof.tHat, e.proof.tauX, e.proof.mu]) src += bn128.bytes(f).slice(2);
        for (let j = 0; j < e.proof.ip.L.length; j++) {
            src += bn128.representation(e.proof.ip.L[j]).slice(2);
            src += bn128.representation(e.proof.ip.R[j]).slice(2);
        }
        src += bn128.bytes(e.proof.ip.a).slice(2);
        src += bn128.bytes(e.proof.ip.b).slice(2);
    }
    const map = new Map(); // pointRep -> scalar
    for (let idx = 0; idx < entries.length; idx++) {
        const { pts, scs } = verifyRangeDecomposed(entries[idx].V, entries[idx].proof, n);
        const alpha = utils.hash(src + bn128.bytes(new BN(idx).toRed(bn128.q)));
        for (let j = 0; j < pts.length; j++) {
            const key = bn128.representation(pts[j]);
            const contrib = scs[j].redMul(alpha);
            const cur = map.get(key);
            map.set(key, cur ? cur.redAdd(contrib) : contrib);
        }
    }
    const keys = [...map.keys()];
    const pts = keys.map(pointFromRep);
    const scs = keys.map((k) => map.get(k));
    return new PointVector(pts).multiExponentiate(new FieldVector(scs)).isInfinity();
}

// Instrumentation variant: recompute the verifier's internal values for the
// self-check test (guards against the tauX and P-reconstruction bugs).
function _debugVerify(Vpoint, proof, n) {
    n = n || params.N;

    const y = hashY(Vpoint, proof.BA, proof.BS);
    const ys = buildYs(y, n);
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();
    const z3 = z.redMul(z2);
    const twoTimesZs = buildTwos(n).times(z2);

    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(z3.redMul(twoPowNMinusOne(n)));

    const x = hashX(z, proof.T1, proof.T2);
    const o = hashO(x, proof.tHat, proof.mu);

    const lhs = params.g.mul(proof.tHat).add(params.h.mul(proof.tauX));
    const rhs = Vpoint.mul(z2).add(params.g.mul(delta)).add(proof.T1.mul(x)).add(proof.T2.mul(x.redSqr()));

    const gsN = params.gs.slice(0, n);
    const hsN = params.hs.slice(0, n);
    const hPrimes = hsN.hadamard(ys.invert());
    let hPrimeSum = bn128.zero;
    for (let i = 0; i < n; i++) {
        hPrimeSum = hPrimeSum.add(hPrimes.getVector()[i].mul(ys.getVector()[i].redMul(z).redAdd(twoTimesZs.getVector()[i])));
    }
    const u = params.h.mul(o);
    let P = proof.BA.add(proof.BS.mul(x)).add(gsN.sum().mul(z.redNeg()))
        .add(hPrimeSum).add(params.h.mul(proof.mu.redNeg())).add(u.mul(proof.tHat));

    return { delta, P, lhs, rhs, y, z, x, o, z2 };
}

// ---- aggregated range proof (m values, Bünz et al. 2018 §4.3) ----
// Proves v_j ∈ [0, 2^n) for all j ∈ [1, m] in a single proof. The m values are
// packed into one m·n-dimension aL vector, and distinguished by z-powers z^{1+j}.
// Proof size = (2⌈log₂(mn)⌉ + 4) G elements + 5 Z_p elements (vs m × single-proof).

const hashYAgg = (Vpoints, BA, BS) => {
    let encoded = "0x";
    for (const V of Vpoints) encoded += bn128.representation(V).slice(2);
    encoded += bn128.representation(BA).slice(2);
    encoded += bn128.representation(BS).slice(2);
    return utils.hash(encoded);
};

// IPA requires a power-of-two vector length. The aggregated proof packs m values
// into one m·n-dimension vector, so m (hence m·n) must be a power of 2. Pad with
// zero values / identity commitments.
const nextPow2 = (x) => {
    let p = 1;
    while (p < x) p <<= 1;
    return p;
};

// twoTimesZs: dim-vector whose j-th n-block is z^{1+j}·2^n (j = 0..m-1).
const buildTwoTimesZsAgg = (m, n, z) => {
    const twos = buildTwos(n);
    const vec = [];
    let zPow = z.redSqr(); // z^2
    for (let j = 0; j < m; j++) {
        for (let k = 0; k < n; k++) vec.push(zPow.redMul(twos.getVector()[k]));
        zPow = zPow.redMul(z);
    }
    return new FieldVector(vec);
};

// Σ_{j=1}^{m} z^{j+2} = z^3 + z^4 + … + z^{m+2}.
const sumZjPlus2 = (m, z) => {
    let acc = new BN(0).toRed(bn128.q);
    let zPow = z.redSqr().redMul(z); // z^3
    for (let j = 0; j < m; j++) {
        acc = acc.redAdd(zPow);
        zPow = zPow.redMul(z);
    }
    return acc;
};

// values: [v_1, …, v_m] (red BNs), blindings: [γ_1, …, γ_m] (red BNs), n: bit-length.
function proveRangeAggregated(values, blindings, n) {
    n = n || params.N;
    const mRaw = values.length;
    if (mRaw === 0 || mRaw !== blindings.length) throw new Error('values and blindings must be non-empty and equal length');
    const m = nextPow2(mRaw);
    const dim = m * n;

    const vs = values.map(v => v.red ? v : v.toRed(bn128.q));
    const gs = blindings.map(r => r.red ? r : r.toRed(bn128.q));
    while (vs.length < m) vs.push(new BN(0).toRed(bn128.q));
    while (gs.length < m) gs.push(new BN(0).toRed(bn128.q));

    const gsN = params.getGs(dim);
    const hsN = params.getHs(dim);

    // 1. aL = concat of m bit decompositions; aR = aL - 1.
    const aLVector = [];
    for (let j = 0; j < m; j++) {
        const v = vs[j];
        for (let i = 0; i < n; i++) aLVector.push(new BN(v.fromRed().ushrn(i).andln(1)).toRed(bn128.q));
    }
    const aL = new FieldVector(aLVector);
    const aR = aL.plus(new BN(1).toRed(bn128.q).redNeg());

    // 2. blinding scalars and random vectors.
    const alpha = bn128.randomScalar();
    const rho = bn128.randomScalar();
    const sL = new FieldVector(Array.from({ length: dim }).map(bn128.randomScalar));
    const sR = new FieldVector(Array.from({ length: dim }).map(bn128.randomScalar));

    const BA = params.h.mul(alpha).add(gsN.multiExponentiate(aL)).add(hsN.multiExponentiate(aR));
    const BS = params.h.mul(rho).add(gsN.multiExponentiate(sL)).add(hsN.multiExponentiate(sR));

    // V_j = g^{v_j} h^{γ_j} (used for the y challenge).
    const Vpoints = vs.map((v, j) => params.g.mul(v).add(params.h.mul(gs[j])));

    // 3. y challenge.
    const y = hashYAgg(Vpoints, BA, BS);
    const ys = buildYs(y, dim);

    // 4. z challenge.
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();

    // 5. twoTimesZs (aggregated).
    const twoTimesZs = buildTwoTimesZsAgg(m, n, z);

    // 6. l(X), r(X).
    const lPoly = new FieldVectorPolynomial(aL.plus(z.redNeg()), sL);
    const rPoly = new FieldVectorPolynomial(ys.hadamard(aR.plus(z)).add(twoTimesZs), ys.hadamard(sR));

    // 7. tPoly = l·r.
    const tPoly = lPoly.innerProduct(rPoly);

    // 8. T1, T2.
    const T1 = PedersenCommitment.commit(tPoly[1]);
    const T2 = PedersenCommitment.commit(tPoly[2]);

    // 9. x challenge.
    const x = hashX(z, T1.point(), T2.point());

    // 10. l(x), r(x), tHat.
    const lEval = lPoly.evaluate(x);
    const rEval = rPoly.evaluate(x);
    const tHat = lEval.innerProduct(rEval);

    // 11. tauX = τ1·x + τ2·x² + Σ_j z^{1+j}·γ_j; mu = α + ρ·x.
    let tauX = T1.randomness.redMul(x).redAdd(T2.randomness.redMul(x.redSqr()));
    let zPow = z.redSqr();
    for (let j = 0; j < m; j++) {
        tauX = tauX.redAdd(zPow.redMul(gs[j]));
        zPow = zPow.redMul(z);
    }
    const mu = alpha.redAdd(rho.redMul(x));

    // 12. o challenge, u, hsPrime.
    const o = hashO(x, tHat, mu);
    const u = params.h.mul(o);
    const hsPrime = hsN.hadamard(ys.invert());

    // 13. P.
    const P = u.mul(tHat).add(gsN.multiExponentiate(lEval)).add(hsPrime.multiExponentiate(rEval));

    // 14. IPA.
    const ip = InnerProductProof.prove(gsN, hsPrime, u, lEval, rEval, o);

    return { BA, BS, T1: T1.point(), T2: T2.point(), tHat, tauX, mu, ip };
}

// Vpoints: [V_1, …, V_m] (the m commitment points), proof: aggregated proof, n: bit-length.
// 逐轮折叠版（对照/回滚用）。
function verifyRangeAggregatedFolding(Vpoints, proof, n) {
    n = n || params.N;
    const mRaw = Vpoints.length;
    if (mRaw === 0) throw new Error('Vpoints must be non-empty');
    const m = nextPow2(mRaw);
    const dim = m * n;

    const Vpts = Vpoints.slice();
    while (Vpts.length < m) Vpts.push(bn128.zero);

    const gsN = params.getGs(dim);
    const hsN = params.getHs(dim);

    // 1. y, ys, z, z2.
    const y = hashYAgg(Vpts, proof.BA, proof.BS);
    const ys = buildYs(y, dim);
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();

    // 2. twoTimesZs.
    const twoTimesZs = buildTwoTimesZsAgg(m, n, z);

    // 3. delta = (z−z²)·⟨1,y⟩ − Σ_j z^{j+2}·(2^n−1).
    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(sumZjPlus2(m, z).redMul(twoPowNMinusOne(n)));

    // 4. x challenge.
    const x = hashX(z, proof.T1, proof.T2);

    // 5. main equation: g^t̂ h^τx == g^δ · Π_j V_j^{z^{1+j}} · T1^x · T2^{x²}.
    const lhs = params.g.mul(proof.tHat).add(params.h.mul(proof.tauX));
    let rhs = params.g.mul(delta);
    let zPow = z.redSqr();
    for (let j = 0; j < m; j++) {
        rhs = rhs.add(Vpts[j].mul(zPow));
        zPow = zPow.redMul(z);
    }
    rhs = rhs.add(proof.T1.mul(x)).add(proof.T2.mul(x.redSqr()));
    if (!lhs.eq(rhs)) return false;

    // 6. hPrimes, hPrimeSum.
    const hPrimes = hsN.hadamard(ys.invert());
    let hPrimeSum = bn128.zero;
    for (let i = 0; i < dim; i++) {
        hPrimeSum = hPrimeSum.add(hPrimes.getVector()[i].mul(ys.getVector()[i].redMul(z).redAdd(twoTimesZs.getVector()[i])));
    }

    // 7. o, u, reconstructed P.
    const o = hashO(x, proof.tHat, proof.mu);
    const u = params.h.mul(o);
    let P = proof.BA.add(proof.BS.mul(x)).add(gsN.sum().mul(z.redNeg()))
        .add(hPrimeSum).add(params.h.mul(proof.mu.redNeg())).add(u.mul(proof.tHat));

    // 8. IPA verification.
    return InnerProductProof.verifyFolding(gsN, hPrimes, u, P, proof.ip, o);
}

// 合并验证（论文 §6.2）——分解版：同 verifyRangeDecomposed，主方程 ΠV_j^{z^{1+j}} 并入 multi-exp。
function verifyRangeAggregatedDecomposed(Vpoints, proof, n) {
    n = n || params.N;
    const mRaw = Vpoints.length;
    if (mRaw === 0) throw new Error('Vpoints must be non-empty');
    const m = nextPow2(mRaw);
    const dim = m * n;
    const logN = Math.log2(dim);

    const Vpts = Vpoints.slice();
    while (Vpts.length < m) Vpts.push(bn128.zero);

    const gsN = params.getGs(dim);
    const hsN = params.getHs(dim);

    // 挑战（与折叠版相同编码顺序）
    const y = hashYAgg(Vpts, proof.BA, proof.BS);
    const ys = buildYs(y, dim);
    const z = utils.hash(bn128.bytes(y));
    const z2 = z.redSqr();
    const twoTimesZs = buildTwoTimesZsAgg(m, n, z);
    const delta = (z.redSub(z2)).redMul(ys.sum()).redSub(sumZjPlus2(m, z).redMul(twoPowNMinusOne(n)));
    const x = hashX(z, proof.T1, proof.T2);
    const o = hashO(x, proof.tHat, proof.mu);
    const u = params.h.mul(o);

    // IPA 各轮挑战 x_j
    const xs = [];
    let prev = o;
    for (let j = 0; j < logN; j++) {
        const xj = utils.hash(abiEncode(
            ['bytes32', 'bytes32[2]', 'bytes32[2]'],
            [bn128.bytes(prev), bn128.serialize(proof.ip.L[j]), bn128.serialize(proof.ip.R[j])]
        ));
        xs.push(xj);
        prev = xj;
    }

    // s_i / t_i
    const one = new BN(1).toRed(bn128.q);
    const s = new Array(dim).fill(one);
    const t = new Array(dim).fill(one);
    for (let j = 0; j < logN; j++) {
        const xj = xs[j];
        const xjInv = xj.redInvm();
        const bit = logN - 1 - j;
        for (let i = 0; i < dim; i++) {
            if (((i >> bit) & 1) === 1) { s[i] = s[i].redMul(xj); t[i] = t[i].redMul(xjInv); }
            else { s[i] = s[i].redMul(xjInv); t[i] = t[i].redMul(xj); }
        }
    }

    // 组合挑战 c（从 Vpoints + 完整证明派生，确定性）
    let cSrc = "0x";
    for (const V of Vpts) cSrc += bn128.representation(V).slice(2);
    for (const f of [proof.BA, proof.BS, proof.T1, proof.T2]) cSrc += bn128.representation(f).slice(2);
    for (const f of [proof.tHat, proof.tauX, proof.mu]) cSrc += bn128.bytes(f).slice(2);
    for (let j = 0; j < logN; j++) {
        cSrc += bn128.representation(proof.ip.L[j]).slice(2);
        cSrc += bn128.representation(proof.ip.R[j]).slice(2);
    }
    cSrc += bn128.bytes(proof.ip.a).slice(2);
    cSrc += bn128.bytes(proof.ip.b).slice(2);
    const c = utils.hash(cSrc);

    // 单次 multi-exponentiation == 无穷远点
    const gv = gsN.getVector(), hv = hsN.getVector(), yv = ys.getVector(), tv = twoTimesZs.getVector();
    const pts = [];
    const scs = [];
    pts.push(params.g);  scs.push(c.redMul(proof.tHat.redSub(delta)));
    pts.push(params.h);  scs.push(c.redMul(proof.tauX).redAdd(proof.mu));
    let zPow = z.redSqr();
    for (let j = 0; j < m; j++) {
        pts.push(Vpts[j]); scs.push(c.redMul(zPow).redNeg());
        zPow = zPow.redMul(z);
    }
    pts.push(proof.T1);  scs.push(c.redMul(x).redNeg());
    pts.push(proof.T2);  scs.push(c.redMul(x.redSqr()).redNeg());
    pts.push(u);         scs.push(proof.ip.a.redMul(proof.ip.b).redSub(proof.tHat));
    pts.push(proof.BA);  scs.push(one.redNeg());
    pts.push(proof.BS);  scs.push(x.redNeg());
    for (let i = 0; i < dim; i++) {
        pts.push(gv[i]); scs.push(z.redAdd(proof.ip.a.redMul(s[i])));
        const yInv = yv[i].redInvm();
        pts.push(hv[i]); scs.push(z.redAdd(tv[i].redMul(yInv)).redNeg().redAdd(proof.ip.b.redMul(t[i]).redMul(yInv)));
    }
    for (let j = 0; j < logN; j++) {
        const xj2 = xs[j].redSqr();
        pts.push(proof.ip.L[j]); scs.push(xj2.redNeg());
        pts.push(proof.ip.R[j]); scs.push(xj2.redInvm().redNeg());
    }

    return { pts, scs };
}

// 单证明聚合验证：一次 multi-exp == 无穷远点。
function verifyRangeAggregated(Vpoints, proof, n) {
    const { pts, scs } = verifyRangeAggregatedDecomposed(Vpoints, proof, n);
    return new PointVector(pts).multiExponentiate(new FieldVector(scs)).isInfinity();
}

// 批量验证多个聚合证明（公共生成元 getGs(dim)/getHs(dim) 共享，只出现一次）。
// entries: [{ Vpoints, proof }, ...]；所有条目必须同 (m, n)（m 取 nextPow2）。
function batchVerifyRangeAggregated(entries, n) {
    if (entries.length === 0) return true;
    let src = "0x";
    for (const e of entries) {
        for (const V of e.Vpoints) src += bn128.representation(V).slice(2);
        for (const f of [e.proof.BA, e.proof.BS, e.proof.T1, e.proof.T2]) src += bn128.representation(f).slice(2);
        for (const f of [e.proof.tHat, e.proof.tauX, e.proof.mu]) src += bn128.bytes(f).slice(2);
        for (let j = 0; j < e.proof.ip.L.length; j++) {
            src += bn128.representation(e.proof.ip.L[j]).slice(2);
            src += bn128.representation(e.proof.ip.R[j]).slice(2);
        }
        src += bn128.bytes(e.proof.ip.a).slice(2);
        src += bn128.bytes(e.proof.ip.b).slice(2);
    }
    const map = new Map();
    for (let idx = 0; idx < entries.length; idx++) {
        const { pts, scs } = verifyRangeAggregatedDecomposed(entries[idx].Vpoints, entries[idx].proof, n);
        const alpha = utils.hash(src + bn128.bytes(new BN(idx).toRed(bn128.q)));
        for (let j = 0; j < pts.length; j++) {
            const key = bn128.representation(pts[j]);
            const contrib = scs[j].redMul(alpha);
            const cur = map.get(key);
            map.set(key, cur ? cur.redAdd(contrib) : contrib);
        }
    }
    const keys = [...map.keys()];
    return new PointVector(keys.map(pointFromRep))
        .multiExponentiate(new FieldVector(keys.map((k) => map.get(k)))).isInfinity();
}

// ---- serialization ----

function serializeProofHex(proof) {
    let result = "0x";
    result += bn128.representation(proof.BA).slice(2);
    result += bn128.representation(proof.BS).slice(2);
    result += bn128.representation(proof.T1).slice(2);
    result += bn128.representation(proof.T2).slice(2);
    result += bn128.bytes(proof.tHat).slice(2);
    result += bn128.bytes(proof.tauX).slice(2);
    result += bn128.bytes(proof.mu).slice(2);
    result += proof.ip.serialize().slice(2);
    return result;
}

function proofToJSON(proof) {
    return {
        BA: bn128.representation(proof.BA),
        BS: bn128.representation(proof.BS),
        T1: bn128.representation(proof.T1),
        T2: bn128.representation(proof.T2),
        tHat: bn128.bytes(proof.tHat),
        tauX: bn128.bytes(proof.tauX),
        mu: bn128.bytes(proof.mu),
        ip: {
            L: proof.ip.L.map(bn128.representation),
            R: proof.ip.R.map(bn128.representation),
            a: bn128.bytes(proof.ip.a),
            b: bn128.bytes(proof.ip.b),
        },
    };
}

function proofFromJSON(json) {
    const ip = new InnerProductProof({
        L: json.ip.L.map(pointFromRep),
        R: json.ip.R.map(pointFromRep),
        a: redFromHex(json.ip.a),
        b: redFromHex(json.ip.b),
    });
    return {
        BA: pointFromRep(json.BA),
        BS: pointFromRep(json.BS),
        T1: pointFromRep(json.T1),
        T2: pointFromRep(json.T2),
        tHat: redFromHex(json.tHat),
        tauX: redFromHex(json.tauX),
        mu: redFromHex(json.mu),
        ip,
    };
}

module.exports = { proveRange, verifyRange, verifyRangeFolding, batchVerifyRange, proveRangeAggregated, verifyRangeAggregated, verifyRangeAggregatedFolding, batchVerifyRangeAggregated, serializeProofHex, proofToJSON, proofFromJSON, _debugVerify };
