// JWK encoding for AP2 `cnf` claims and payee keys.
//
// AP2 carries keys as JWKs (`cnf.jwk` in open mandates; the published examples use
// P-256). This prototype runs secp256k1 end to end, which JWK supports via RFC 8812
// (`crv: "secp256k1"`), so the claim shape stays conformant while the curve matches
// the rest of the implementation.

const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const { base64url, base64urlDecode } = require('./hashes');

const CRV = 'secp256k1';

// Compressed public key hex -> JWK.
function pubToJwk(pkHex) {
    const key = ec.keyFromPublic(pkHex, 'hex');
    const p = key.getPublic();
    return {
        kty: 'EC',
        crv: CRV,
        x: base64url(Buffer.from(p.getX().toArray('be', 32))),
        y: base64url(Buffer.from(p.getY().toArray('be', 32))),
    };
}

// JWK -> compressed public key hex.
function jwkToPub(jwk) {
    if (!isJwk(jwk)) throw new Error(`Unsupported JWK (expected kty=EC, crv=${CRV})`);
    const x = base64urlDecode(jwk.x).toString('hex').padStart(64, '0');
    const y = base64urlDecode(jwk.y).toString('hex').padStart(64, '0');
    return ec.keyFromPublic({ x, y }).getPublic(true, 'hex');
}

function isJwk(jwk) {
    return !!(jwk && jwk.kty === 'EC' && jwk.crv === CRV
        && typeof jwk.x === 'string' && typeof jwk.y === 'string');
}

module.exports = { pubToJwk, jwkToPub, isJwk, CRV };
