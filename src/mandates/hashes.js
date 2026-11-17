// Spec-defined hashing and encodings for AP2 mandates (Node-only).
//
// AP2 pins the hash for checkout_hash / transaction_id / sd_hash to `_sd_alg`
// (sha-256 in every published example) and encodes digests as base64url. Under
// the SD-JWT encoding both inputs are wire artefacts — a JWS compact string or a
// presentation string — so the digest is taken over the exact bytes that cross
// the wire. The old canonical-JSON substitute for whole mandates is gone.
//
// Uses node:crypto, so it is imported by the servers and scripts, never by the
// browser bundle.

const { createHash } = require('crypto');

function sha256Bytes(buf) {
    return createHash('sha256').update(buf).digest();
}

function base64url(buf) {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
    const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
    return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

// base64url(sha256(utf8(str))) — the shape AP2 uses for checkout_hash,
// transaction_id, sd_hash and a receipt's `reference`.
function hashB64Url(str) {
    return base64url(sha256Bytes(Buffer.from(str, 'utf8')));
}

// sd_hash = base64url(SHA-256(presentation)). Accepts the presentation string
// itself, or an SD-JWT mandate handle (whose default presentation — every
// disclosure — is hashed), which is what the builders bind to.
function hashPresented(presented) {
    if (typeof presented === 'string') {
        if (presented.length === 0) throw new Error('presentation must be a non-empty string');
        return hashB64Url(presented);
    }
    if (presented && typeof presented.present === 'function') {
        return hashB64Url(presented.present());
    }
    throw new Error('expected an SD-JWT presentation string or a mandate handle');
}

// checkout_hash / transaction_id = base64url(SHA-256(checkout_jwt)), where
// checkout_jwt is the merchant-signed JWS compact string.
function checkoutHashOf(checkoutJwt) {
    if (typeof checkoutJwt !== 'string' || checkoutJwt.length === 0) {
        throw new Error('checkout JWT must be a non-empty string');
    }
    return hashB64Url(checkoutJwt);
}

module.exports = {
    sha256Bytes,
    base64url,
    base64urlDecode,
    hashB64Url,
    hashPresented,
    checkoutHashOf,
};
