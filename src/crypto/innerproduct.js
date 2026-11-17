// Inner-product argument (IPA) — REFACTORED port from
// anonymous-zether packages/anonymous.js/src/prover/innerproduct.js.
//
// The reference mutated the global mutable PedersenVectorCommitment.base during
// recursion (and restored it after). That global state is eliminated: all
// generator vectors are passed explicitly as parameters and are purely local.
const bn128 = require('./bn128.js');
const BN = require('bn.js');
const utils = require('./utils.js');
const { abiEncode } = require('./keccak.js');
const { PointVector, FieldVector } = require('./algebra.js');

class InnerProductProof {
    constructor({ L, R, a, b } = {}) {
        this.L = L || [];
        this.R = R || [];
        this.a = a;
        this.b = b;
    }

    serialize() {
        let result = "0x";
        this.L.forEach((l) => { result += bn128.representation(l).slice(2); });
        this.R.forEach((r) => { result += bn128.representation(r).slice(2); });
        result += bn128.bytes(this.a).slice(2);
        result += bn128.bytes(this.b).slice(2);
        return result;
    }

    // gs, hs: PointVector (length n, power of two); u: elliptic point (= h·o);
    // a, b: FieldVector; salt: red BN.
    static prove(gs, hs, u, a, b, salt) {
        const result = new InnerProductProof();

        const recursiveProof = (result, gs, hs, as, bs, previousChallenge) => {
            const n = as.length();
            if (n === 1) {
                result.a = as.getVector()[0];  //最终的标量a和b
                result.b = bs.getVector()[0];
                return;
            }
            const nPrime = n / 2;
            const asLeft = as.slice(0, nPrime);   //求各向量的左右两半子向量
            const asRight = as.slice(nPrime);
            const bsLeft = bs.slice(0, nPrime);
            const bsRight = bs.slice(nPrime);
            const gsLeft = gs.slice(0, nPrime);
            const gsRight = gs.slice(nPrime);
            const hsLeft = hs.slice(0, nPrime);
            const hsRight = hs.slice(nPrime);

            const cL = asLeft.innerProduct(bsRight);
            const cR = asRight.innerProduct(bsLeft);
            const L = gsRight.multiExponentiate(asLeft).add(hsLeft.multiExponentiate(bsRight)).add(u.mul(cL));
            const R = gsLeft.multiExponentiate(asRight).add(hsRight.multiExponentiate(bsLeft)).add(u.mul(cR));
            result.L.push(L);
            result.R.push(R);

            const x = utils.hash(abiEncode(
                ['bytes32', 'bytes32[2]', 'bytes32[2]'],
                [bn128.bytes(previousChallenge), bn128.serialize(L), bn128.serialize(R)]
            ));

            const xInv = x.redInvm(); //x的逆
            const gsPrime = gsLeft.times(xInv).add(gsRight.times(x));
            const hsPrime = hsLeft.times(x).add(hsRight.times(xInv));
            const asPrime = asLeft.times(x).add(asRight.times(xInv));
            const bsPrime = bsLeft.times(xInv).add(bsRight.times(x));

            recursiveProof(result, gsPrime, hsPrime, asPrime, bsPrime, x);
        };
        recursiveProof(result, gs, hs, a, b, salt);
        return result;
    }

    // Simple folding verifier: recompute per-round challenges, fold P and the
    // generator vectors, then check the length-1 relation.
    // Equivalent to InnerProductVerifier.sol's single-inversion s[] construction.
    static verifyFolding(gs, hs, u, P, proof, salt) {
        const n = gs.length();
        const logN = Math.log2(n);

        let prev = salt;
        let Pacc = P;
        let gsf = gs;
        let hsf = hs;
        for (let i = 0; i < logN; i++) {
            const L = proof.L[i];
            const R = proof.R[i];
            const x = utils.hash(abiEncode(
                ['bytes32', 'bytes32[2]', 'bytes32[2]'],
                [bn128.bytes(prev), bn128.serialize(L), bn128.serialize(R)]
            ));
            const xInv = x.redInvm();
            Pacc = Pacc.add(L.mul(x.redSqr())).add(R.mul(xInv.redSqr()));
            const nPrime = gsf.length() / 2;
            const gsL = gsf.slice(0, nPrime);
            const gsR = gsf.slice(nPrime);
            const hsL = hsf.slice(0, nPrime);
            const hsR = hsf.slice(nPrime);
            gsf = gsL.times(xInv).add(gsR.times(x));
            hsf = hsL.times(x).add(hsR.times(xInv));
            prev = x;
        }

        // after log2(n) rounds gsf/hsf have length 1
        const expected = u.mul(proof.a.redMul(proof.b))
            .add(gsf.getVector()[0].mul(proof.a))
            .add(hsf.getVector()[0].mul(proof.b));
        return expected.eq(Pacc);
    }

    // Delayed-fold verifier (Bünz et al. §3.1): record the per-round challenges
    // but do NOT fold the generator vectors every round (that costs O(n) point
    // multiplications per round, ~4n total). Instead, after the last round,
    // reconstruct g_final = Σ_i g_i^{s_i} and h_final = Σ_i h_i^{t_i} with a
    // single multi-exponentiation each, where s_i (resp. t_i) are Z_p products
    // of the challenges. Total point multiplications: ~2n + 2·log₂n + 3.
    static verify(gs, hs, u, P, proof, salt) {
        const n = gs.length();
        const logN = Math.log2(n);

        let prev = salt;
        let Pacc = P;
        const xs = [];
        for (let i = 0; i < logN; i++) {
            const L = proof.L[i];
            const R = proof.R[i];
            const x = utils.hash(abiEncode(
                ['bytes32', 'bytes32[2]', 'bytes32[2]'],
                [bn128.bytes(prev), bn128.serialize(L), bn128.serialize(R)]
            ));
            const xInv = x.redInvm();
            Pacc = Pacc.add(L.mul(x.redSqr())).add(R.mul(xInv.redSqr()));
            xs.push(x);
            prev = x;
        }

        // s_i = Π_j x_j^{b(i,j)},  t_i = Π_j x_j^{-b(i,j)},
        // where b(i,j) = +1 iff bit (logN-1-j) of i is 1: folding halves from
        // the MSB down, so round j (0-based) splits on bit logN-1-j
        // (g_left×x⁻¹, g_right×x).
        const one = new BN(1).toRed(bn128.q);
        const gv = gs.getVector();
        const hv = hs.getVector();
        const s = new Array(n).fill(one);
        const t = new Array(n).fill(one);
        for (let j = 0; j < logN; j++) {
            const x = xs[j];
            const xInv = x.redInvm();
            const bit = logN - 1 - j;
            for (let i = 0; i < n; i++) {
                if (((i >> bit) & 1) === 1) { s[i] = s[i].redMul(x); t[i] = t[i].redMul(xInv); }
                else { s[i] = s[i].redMul(xInv); t[i] = t[i].redMul(x); }
            }
        }
        const gFinal = new PointVector(gv).multiExponentiate(new FieldVector(s));
        const hFinal = new PointVector(hv).multiExponentiate(new FieldVector(t));
        const expected = u.mul(proof.a.redMul(proof.b))
            .add(gFinal.mul(proof.a))
            .add(hFinal.mul(proof.b));
        return expected.eq(Pacc);
    }
}

module.exports = InnerProductProof;
