// Hash-to-curve / Fiat-Shamir helpers — trimmed port from
// anonymous-zether packages/anonymous.js/src/utils/utils.js, with the
// web3 soliditySha3 dependency replaced by the self-contained keccak.js.
// Kept: mapInto, hash, createAccount. Dropped: sign, readBalance, gEpoch, u.
const bn128 = require('./bn128.js');
const BN = require('bn.js');
const { keccak256Hex } = require('./keccak.js');

const utils = {};

utils.createAccount = () => {
    const x = bn128.randomScalar();
    const y = bn128.curve.g.mul(x);
    return { 'x': x, 'y': y };
};

utils.mapInto = (seed) => { // seed is flattened 0x + hex string
    const seed_red = new BN(seed.slice(2), 16).toRed(bn128.p);
    const p_1_4 = bn128.curve.p.add(new BN(1)).div(new BN(4));
    while (true) {
        const y_squared = seed_red.redPow(new BN(3)).redAdd(bn128.b.toRed(bn128.p));
        const y = y_squared.redPow(p_1_4);
        if (y.redPow(new BN(2)).eq(y_squared)) {
            return bn128.curve.point(seed_red.fromRed(), y.fromRed());
        }
        seed_red.redIAdd(new BN(1).toRed(bn128.p));
    }
};

utils.hash = (encoded) => { // encoded 为 "0x"+hex（ABI 编码），与 web3 soliditySha3 字节等价
    return new BN(keccak256Hex(encoded), 16).toRed(bn128.q);
};

module.exports = utils;
