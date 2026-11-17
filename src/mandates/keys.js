// ECDSA key generation, signing, verification using secp256k1 (via elliptic).
// Separate curve from the BN128 ZKP layer — standard delegation crypto.
// Works in Node and browser (elliptic uses brorand which falls back to crypto.getRandomValues).

const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const { keccak256Hex } = require('../crypto/keccak');

// Generate a secp256k1 keypair.
function generateKeypair() {
    const key = ec.genKeyPair();
    return {
        sk: key.getPrivate('hex'),
        pk: key.getPublic(true, 'hex'),  // compressed public key
    };
}

// Load key from private hex.
function fromPrivate(skHex) {
    return ec.keyFromPrivate(skHex);
}

// Sign a message hash (hex, 0x-prefixed) with a private key.
// Returns DER-encoded hex signature.
function sign(hashHex, skHex) {
    const key = fromPrivate(skHex);
    const sig = key.sign(hashHex.slice(2)); // strip 0x for elliptic
    return sig.toDER('hex');
}

// Verify a message hash against a DER signature.
function verify(hashHex, sigHex, pkHex) {
    try {
        const key = ec.keyFromPublic(pkHex, 'hex');
        return key.verify(hashHex.slice(2), sigHex);
    } catch (e) {
        return false;
    }
}

// Deterministic JSON serialisation: keys sorted at every nesting level, no
// whitespace. Note that JSON.stringify(obj, keysArray) is NOT usable here — an
// array replacer applies the same key list to nested objects, which silently
// drops them (e.g. constraints and checkoutRef serialise as {}).
function canonicalize(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(canonicalize).join(',') + ']';
    }
    const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined && typeof value[k] !== 'function')
        .sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

// UTF-8 bytes as hex, without Buffer (works in Node and browsers).
function utf8Hex(str) {
    let hex = '';
    for (const byte of new TextEncoder().encode(str)) {
        hex += byte.toString(16).padStart(2, '0');
    }
    return hex;
}

// Hash a JSON object canonically (sorted keys at all levels, no whitespace).
function hashJSON(obj) {
    return '0x' + keccak256Hex('0x' + utf8Hex(canonicalize(obj)));
}

module.exports = { generateKeypair, fromPrivate, sign, verify, hashJSON, ec };
