// SD-JWT primitives for the AP2 prototype: JWS compact serialisation with
// ES256K, salted disclosures, presentation strings and key binding (kb-sd-jwt).
//
// Contract: docs/sdjwt-contract.md section 1. Signatures are ECDSA secp256k1
// over SHA-256(signing input), encoded in JWS as raw 64-byte r||s (base64url).
// keys.sign/keys.verify take a 0x-prefixed hex *digest* and use DER internally,
// so this module converts between the two encodings locally.
//
// Only node:crypto, ./keys and ./hashes are used.

const { randomBytes } = require('crypto');
const keys = require('./keys');
const { base64url, base64urlDecode, hashB64Url, sha256Bytes } = require('./hashes');

const ALG = 'ES256K';
const DEFAULT_HEADER = { alg: ALG, typ: 'JWT' };
const SD_ALG = 'sha-256';
const RESERVED_CLAIMS = new Set(['_sd', '_sd_alg']);

// ---- encoding helpers (built on hashes.js, not duplicated there) ----

function b64uFromString(str) {
    return base64url(Buffer.from(str, 'utf8'));
}

function b64uToString(str) {
    return base64urlDecode(str).toString('utf8');
}

// 0x-prefixed hex digest of a UTF-8 string, the input shape keys.sign/verify expect.
function digestHex(str) {
    return '0x' + sha256Bytes(Buffer.from(str, 'utf8')).toString('hex');
}

// ---- DER <-> raw r||s conversion for signatures ----

function fixedWidth32(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const value = bytes.subarray(start);
    if (value.length > 32) throw new Error('invalid DER signature: integer too large');
    return Buffer.concat([Buffer.alloc(32 - value.length), value]);
}

// DER (as produced by keys.sign) -> 64-byte r||s buffer.
function derToRaw(derHex) {
    const der = Buffer.from(String(derHex).replace(/^0x/, ''), 'hex');
    let off = 0;

    function readLength() {
        let len = der[off++];
        if (len & 0x80) {
            const count = len & 0x7f;
            len = 0;
            for (let i = 0; i < count; i++) len = (len << 8) | der[off++];
        }
        return len;
    }

    if (der[off++] !== 0x30) throw new Error('invalid DER signature: expected SEQUENCE');
    const seqLen = readLength();
    if (seqLen !== der.length - off) throw new Error('invalid DER signature: bad SEQUENCE length');

    function readInteger() {
        if (der[off++] !== 0x02) throw new Error('invalid DER signature: expected INTEGER');
        const len = readLength();
        const value = der.subarray(off, off + len);
        if (value.length !== len) throw new Error('invalid DER signature: truncated INTEGER');
        off += len;
        return value;
    }

    const r = readInteger();
    const s = readInteger();
    if (off !== der.length) throw new Error('invalid DER signature: trailing bytes');
    return Buffer.concat([fixedWidth32(r), fixedWidth32(s)]);
}

// Minimal big-endian INTEGER encoding of a 32-byte r/s value.
function derInteger(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let value = bytes.subarray(start);
    if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0x00]), value]);
    return Buffer.concat([Buffer.from([0x02, value.length]), value]);
}

// 64-byte r||s buffer -> DER hex, the input shape keys.verify expects. That
// function passes the signature straight to elliptic, which does not accept a
// 0x prefix on the signature (only the digest is 0x-prefixed).
function rawToDer(raw) {
    const body = Buffer.concat([derInteger(raw.subarray(0, 32)), derInteger(raw.subarray(32, 64))]);
    return Buffer.concat([Buffer.from([0x30, body.length]), body]).toString('hex');
}

// ---- JWS compact serialisation ----

// Sign a payload object as a JWS compact string. `opts.header` may add extra
// header fields (e.g. kid), but alg/typ are always the contract's ES256K/JWT.
function signJws(payload, skHex, opts = {}) {
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('JWS payload must be a plain object');
    }
    if (typeof skHex !== 'string' || skHex.length === 0) throw new Error('skHex is required');
    const header = Object.assign({}, opts.header || {}, DEFAULT_HEADER);
    const signingInput = b64uFromString(JSON.stringify(header)) + '.' +
        b64uFromString(JSON.stringify(payload));
    const derHex = keys.sign(digestHex(signingInput), skHex);
    return signingInput + '.' + base64url(derToRaw(derHex));
}

// Decode a JWS compact string without verifying it. Throws on malformed input.
function decodeJws(jws) {
    if (typeof jws !== 'string') throw new Error('JWS must be a string');
    const parts = jws.split('.');
    if (parts.length !== 3) throw new Error('JWS must have exactly three dot-separated segments');
    const [headerB64u, payloadB64u, signatureB64u] = parts;
    if (!headerB64u || !payloadB64u || !signatureB64u) throw new Error('JWS segments must be non-empty');

    let header;
    let payload;
    try {
        header = JSON.parse(b64uToString(headerB64u));
    } catch (e) {
        throw new Error('JWS header is not valid base64url-encoded JSON');
    }
    try {
        payload = JSON.parse(b64uToString(payloadB64u));
    } catch (e) {
        throw new Error('JWS payload is not valid base64url-encoded JSON');
    }
    if (header === null || typeof header !== 'object' || Array.isArray(header)) {
        throw new Error('JWS header must be a JSON object');
    }
    return {
        header,
        payload,
        signingInput: headerB64u + '.' + payloadB64u,
        signatureB64u,
    };
}

// Verify a JWS compact string with the issuer/holder public key.
function verifyJws(jws, pkHex) {
    let decoded;
    try {
        decoded = decodeJws(jws);
    } catch (e) {
        return { ok: false, reason: e.message };
    }
    if (decoded.header.alg !== ALG) {
        return { ok: false, reason: 'unsupported alg: ' + decoded.header.alg };
    }
    let raw;
    try {
        raw = base64urlDecode(decoded.signatureB64u);
    } catch (e) {
        return { ok: false, reason: 'JWS signature is not valid base64url' };
    }
    if (raw.length !== 64) {
        return { ok: false, reason: 'JWS signature must be 64 bytes (r||s)' };
    }
    let ok = false;
    try {
        ok = keys.verify(digestHex(decoded.signingInput), rawToDer(raw), pkHex);
    } catch (e) {
        ok = false;
    }
    if (!ok) return { ok: false, reason: 'invalid JWS signature' };
    return { ok: true, payload: decoded.payload, header: decoded.header };
}

// ---- disclosures ----

// base64url(JSON.stringify([salt, claimName, claimValue])), salt = 16 random bytes.
function makeDisclosure(claimName, claimValue) {
    if (typeof claimName !== 'string' || claimName.length === 0) {
        throw new Error('claim name must be a non-empty string');
    }
    const salt = base64url(randomBytes(16));
    return b64uFromString(JSON.stringify([salt, claimName, claimValue]));
}

// base64url(SHA-256(disclosure)) over the UTF-8 bytes of the disclosure string.
function disclosureDigest(disclosureB64u) {
    if (typeof disclosureB64u !== 'string' || disclosureB64u.length === 0) {
        throw new Error('disclosure must be a non-empty base64url string');
    }
    return hashB64Url(disclosureB64u);
}

function parseDisclosure(disclosureB64u) {
    if (typeof disclosureB64u !== 'string' || disclosureB64u.length === 0) {
        throw new Error('disclosure must be a non-empty base64url string');
    }
    let decoded;
    try {
        decoded = JSON.parse(b64uToString(disclosureB64u));
    } catch (e) {
        throw new Error('disclosure is not valid base64url-encoded JSON');
    }
    if (!Array.isArray(decoded) || decoded.length !== 3) {
        throw new Error('disclosure must be a [salt, name, value] array');
    }
    const [salt, name] = decoded;
    if (typeof salt !== 'string' || salt.length === 0) {
        throw new Error('disclosure salt must be a non-empty string');
    }
    if (typeof name !== 'string' || name.length === 0) {
        throw new Error('disclosure claim name must be a non-empty string');
    }
    return decoded;
}

// ---- SD-JWT issuance and presentation ----

// Issue an SD-JWT: `disclosable` claims are removed from the payload and
// committed as digests in `_sd`; their disclosures are returned separately.
function issueSdJwt({ claims, disclosable = [], skHex } = {}) {
    if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
        throw new Error('claims must be a plain object');
    }
    if (!Array.isArray(disclosable)) throw new Error('disclosable must be an array of claim names');
    if (typeof skHex !== 'string' || skHex.length === 0) throw new Error('skHex is required');

    const payload = Object.assign({}, claims);
    delete payload._sd;
    delete payload._sd_alg;

    const disclosures = [];
    const digestByName = {};
    const seenNames = new Set();
    for (const name of disclosable) {
        if (typeof name !== 'string' || name.length === 0) {
            throw new Error('disclosable claim names must be non-empty strings');
        }
        if (seenNames.has(name)) throw new Error('duplicate disclosable claim: ' + name);
        if (RESERVED_CLAIMS.has(name)) throw new Error('cannot disclose reserved claim: ' + name);
        if (!Object.prototype.hasOwnProperty.call(payload, name)) {
            throw new Error('disclosable claim not present in claims: ' + name);
        }
        seenNames.add(name);
        const disclosure = makeDisclosure(name, payload[name]);
        disclosures.push(disclosure);
        digestByName[name] = disclosureDigest(disclosure);
        delete payload[name];
    }

    payload._sd_alg = SD_ALG;
    payload._sd = disclosures.map((d) => disclosureDigest(d));

    return { sdjwt: signJws(payload, skHex), disclosures, digestByName };
}

// Presentation = jwt + "~" + disclosures.join("~"); zero disclosures keeps the
// trailing separator, so a presentation always contains at least one "~".
function present({ sdjwt, disclosures = [] } = {}) {
    if (typeof sdjwt !== 'string' || sdjwt.length === 0) throw new Error('sdjwt is required');
    if (!Array.isArray(disclosures)) throw new Error('disclosures must be an array');
    for (const disclosure of disclosures) {
        if (typeof disclosure !== 'string' || disclosure.length === 0) {
            throw new Error('disclosures must be non-empty base64url strings');
        }
    }
    return sdjwt + '~' + disclosures.join('~');
}

// Split a presentation string into its JWT and presented disclosures. The
// optional trailing "~" is accepted, empty middle segments are ignored.
function parsePresentation(presentation) {
    if (typeof presentation !== 'string' || presentation.length === 0) {
        throw new Error('presentation must be a non-empty string');
    }
    const parts = presentation.split('~');
    const jwt = parts[0];
    if (!jwt) throw new Error('presentation is missing the SD-JWT');
    const disclosures = parts.slice(1).filter((part) => part.length > 0);
    return { jwt, disclosures };
}

// Verify a presentation against a trusted issuer key and merge the presented
// disclosures into the returned claims. Undisclosed claims stay absent.
function verifyPresentation({ presentation, issuerPubkey, requiredClaims = [] } = {}) {
    let parsed;
    try {
        parsed = parsePresentation(presentation);
    } catch (e) {
        return { ok: false, reason: e.message };
    }

    const verified = verifyJws(parsed.jwt, issuerPubkey);
    if (!verified.ok) return { ok: false, reason: verified.reason || 'invalid JWS signature' };

    const payload = verified.payload;
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
        return { ok: false, reason: 'JWS payload must be a JSON object' };
    }
    if (payload._sd_alg !== SD_ALG) {
        return { ok: false, reason: '_sd_alg must be "' + SD_ALG + '"' };
    }
    if (payload._sd !== undefined && !Array.isArray(payload._sd)) {
        return { ok: false, reason: '_sd must be an array of digests' };
    }
    const committed = new Set(payload._sd || []);

    // Non-disclosable claims come straight from the signed payload.
    const claims = {};
    for (const [name, value] of Object.entries(payload)) {
        if (!RESERVED_CLAIMS.has(name)) claims[name] = value;
    }

    const disclosed = {};
    const seenDigests = new Set();
    for (const disclosure of parsed.disclosures) {
        let digest;
        try {
            digest = disclosureDigest(disclosure);
        } catch (e) {
            return { ok: false, reason: 'malformed disclosure: ' + e.message };
        }
        if (seenDigests.has(digest)) return { ok: false, reason: 'duplicate disclosure' };
        seenDigests.add(digest);
        if (!committed.has(digest)) {
            return { ok: false, reason: 'disclosure digest is not committed in _sd' };
        }

        let parsedDisclosure;
        try {
            parsedDisclosure = parseDisclosure(disclosure);
        } catch (e) {
            return { ok: false, reason: 'malformed disclosure: ' + e.message };
        }
        const name = parsedDisclosure[1];
        const value = parsedDisclosure[2];
        if (RESERVED_CLAIMS.has(name) || Object.prototype.hasOwnProperty.call(payload, name)) {
            return { ok: false, reason: 'disclosure overrides non-disclosable claim: ' + name };
        }
        claims[name] = value;
        disclosed[name] = value;
    }

    if (!Array.isArray(requiredClaims)) throw new Error('requiredClaims must be an array');
    const missing = requiredClaims.filter((name) => !Object.prototype.hasOwnProperty.call(claims, name));
    if (missing.length > 0) {
        return { ok: false, reason: 'missing required claims: ' + missing.join(', ') };
    }

    return { ok: true, claims, disclosed };
}

// ---- key binding (kb-sd-jwt) ----

function sdHashOf(presentation) {
    if (typeof presentation !== 'string' || presentation.length === 0) {
        throw new Error('presentation must be a non-empty string');
    }
    return hashB64Url(presentation);
}

// Build the holder's kb-jwt over a presentation. Payload is exactly
// { nonce, aud, iat, sd_hash }; `holderPk` is accepted for API symmetry but is
// not embedded, per contract.
function buildKbJwt({ presentation, nonce, aud, holderSk } = {}) {
    if (typeof holderSk !== 'string' || holderSk.length === 0) throw new Error('holderSk is required');
    if (typeof nonce !== 'string' || nonce.length === 0) throw new Error('nonce is required');
    if (typeof aud !== 'string' || aud.length === 0) throw new Error('aud is required');
    const payload = {
        nonce,
        aud,
        iat: Math.floor(Date.now() / 1000),
        sd_hash: sdHashOf(presentation),
    };
    return signJws(payload, holderSk);
}

// Verify a kb-jwt against the holder key, the original presentation and the
// verifier-issued nonce/audience.
function verifyKbJwt({ kbJwt, presentation, nonce, aud, holderPubkey } = {}) {
    const verified = verifyJws(kbJwt, holderPubkey);
    if (!verified.ok) return { ok: false, reason: verified.reason || 'invalid kb-jwt signature' };

    const payload = verified.payload;
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
        return { ok: false, reason: 'kb-jwt payload must be a JSON object' };
    }
    if (payload.nonce !== nonce) return { ok: false, reason: 'kb-jwt nonce mismatch' };
    if (payload.aud !== aud) return { ok: false, reason: 'kb-jwt aud mismatch' };

    let expected;
    try {
        expected = sdHashOf(presentation);
    } catch (e) {
        return { ok: false, reason: e.message };
    }
    if (payload.sd_hash !== expected) return { ok: false, reason: 'kb-jwt sd_hash mismatch' };

    return { ok: true };
}

module.exports = {
    signJws,
    verifyJws,
    decodeJws,
    makeDisclosure,
    disclosureDigest,
    parseDisclosure,
    issueSdJwt,
    present,
    parsePresentation,
    verifyPresentation,
    buildKbJwt,
    verifyKbJwt,
};
