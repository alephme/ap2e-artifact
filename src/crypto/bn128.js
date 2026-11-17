// BN128 / secp256k1 curve layer — ported from anonymous-zether packages/anonymous.js/src/utils/bn128.js.
// Uses globalThis.crypto.getRandomValues for Node >= 18 and browser compatibility.
//
// Select curve via ZKP_CURVE env var:
//   ZKP_CURVE=bn128     (default) 254-bit pairing-friendly, ~128-bit security
//   ZKP_CURVE=secp256k1            256-bit Bitcoin curve, ~128-bit security
const BN = require('bn.js');
const EC = require('elliptic');

// CSPRNG: 32 bytes via globalThis.crypto (available in Node >= 18 and browsers).
// brorand inside elliptic already uses the same path.
function randomBytes32() {
    const buf = new Uint8Array(32);
    globalThis.crypto.getRandomValues(buf);
    let hex = '';
    for (let i = 0; i < buf.length; i++) hex += buf[i].toString(16).padStart(2, '0');
    return hex;
}

const CURVE = process.env.ZKP_CURVE || 'bn128';

const B_MAX = 4294967295;
const empty = "0x0000000000000000000000000000000000000000000000000000000000000000";
const bn128 = {};

if (CURVE === 'secp256k1') {
    // secp256k1: a=0, b=7, p ≈ 2^256, n ≈ 2^256, ~128-bit security.
    const FIELD_MODULUS = new BN("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    const GROUP_MODULUS = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

    bn128.curve = new EC.curve.short({
        a: '0',
        b: '7',
        p: FIELD_MODULUS,
        n: GROUP_MODULUS,
        gRed: false,
        g: ['79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'],
    });
    bn128.b = new BN(7);
} else {
    // BN128 (default): a=0, b=3, p ≈ 2^254, n ≈ 2^254, ~128-bit security.
    const FIELD_MODULUS = new BN("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16);
    const GROUP_MODULUS = new BN("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16);

    bn128.curve = new EC.curve.short({
        a: '0',
        b: '3',
        p: FIELD_MODULUS,
        n: GROUP_MODULUS,
        gRed: false,
        g: ['077da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4',
            '01485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875'],
    });
    bn128.b = new BN(3);
}

bn128.zero = bn128.curve.g.mul(0);

bn128.p = BN.red(bn128.curve.p);
bn128.q = BN.red(bn128.curve.n);

bn128.randomScalar = () => new BN(randomBytes32(), 16).toRed(bn128.q);
bn128.bytes = (i) => "0x" + i.toString(16, 64);
bn128.serialize = (point) => { // differs from point.encode('hex'). ethereum-compatible
    if (point.x === null && point.y === null) return [empty, empty];
    return [bn128.bytes(point.getX()), bn128.bytes(point.getY())];
};
bn128.representation = (point) => { // essentially for serializing proofs...
    if (point.x === null && point.y === null) return empty + empty.slice(2);
    return bn128.bytes(point.getX()) + bn128.bytes(point.getY()).slice(2);
};
bn128.deserialize = (serialization) => {
    if (serialization[0] === empty && serialization[1] === empty) return bn128.zero;
    return bn128.curve.point(serialization[0].slice(2), serialization[1].slice(2)); // no check if valid curve point?
};

bn128.B_MAX = B_MAX;

module.exports = bn128;
