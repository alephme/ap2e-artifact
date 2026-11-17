// ECIES over BN128 with WebCrypto AES-256-GCM (works in Node >= 18 and browsers).
//   keypair: sk = random scalar, pk = g·sk
//   shared secret S = pk·k = K·sk; AES key = SHA-256(domain || x-coordinate of S)
const bn128 = require('./bn128.js');

const DOMAIN = 'zkp-demo/ecies/v1';

// ---- local hex<->bytes helpers ----

const hexToBytes = (hex) => {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length % 2 !== 0) throw new Error('odd-length hex string');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
};

const bytesToHex = (buf) => {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
};

const utf8Bytes = (s) => new TextEncoder().encode(s);
const utf8String = (buf) => new TextDecoder().decode(buf);

const pointFromRep = (rep) => {
    const hex = rep.startsWith('0x') ? rep.slice(2) : rep;
    return bn128.deserialize(['0x' + hex.slice(0, 64), '0x' + hex.slice(64)]);
};

// ---- keypair ----

function generateKeypair() {
    const sk = bn128.randomScalar();
    const pk = bn128.curve.g.mul(sk);
    return { sk, pk };
}

// ---- AES-GCM key derivation from the ECDH shared point S ----

async function deriveKey(S) {
    const xBytes = hexToBytes(bn128.bytes(S.getX()));
    const domain = utf8Bytes(DOMAIN);
    const concat = new Uint8Array(domain.length + xBytes.length);
    concat.set(domain, 0);
    concat.set(xBytes, domain.length);
    const keyData = await globalThis.crypto.subtle.digest('SHA-256', concat);
    return globalThis.crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encrypt(pk, plaintextUtf8) {
    const k = bn128.randomScalar();
    const K = bn128.curve.g.mul(k); // ephemeral public
    const S = pk.mul(k);            // shared secret
    const key = await deriveKey(S);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ctTag = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8Bytes(plaintextUtf8));
    // WebCrypto appends the 16-byte tag to the ciphertext: output = iv || tag(16) || ciphertext
    const tag = new Uint8Array(ctTag.slice(0, 16));
    const ct = new Uint8Array(ctTag.slice(16));
    return {
        ephemeralHex: bn128.representation(K),
        ivHex: bytesToHex(iv),
        tagHex: bytesToHex(tag),
        ciphertextHex: bytesToHex(ct),
    };
}

// Throws on authentication failure.
async function decrypt(sk, envelope) {
    const K = pointFromRep(envelope.ephemeralHex);
    const S = K.mul(sk); // shared secret
    const key = await deriveKey(S);
    const iv = hexToBytes(envelope.ivHex);
    const tag = hexToBytes(envelope.tagHex);
    const ct = hexToBytes(envelope.ciphertextHex);
    const combined = new Uint8Array(tag.length + ct.length);
    combined.set(tag, 0);
    combined.set(ct, tag.length);
    const plain = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
    return utf8String(plain);
}

module.exports = { generateKeypair, encrypt, decrypt };
