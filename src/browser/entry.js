// Browser-compatible crypto bundle entry point.
// Bundled with esbuild into src/web/shared/crypto-bundle.js
// Exports the subset of crypto needed by the browser-based User Client.

const bn128 = require('../crypto/bn128');
const { randomCommit, commit, difference, pointToHex, hexToPoint, openingToJson, parseOpening } = require('../shopping/commitments');
const ecies = require('../crypto/ecies');
const keys = require('../mandates/keys');
const mandate = require('../mandates/mandate');

// Re-export everything the browser needs.
const ZKP = {
    // bn128 helpers
    randomScalar: bn128.randomScalar,
    pointToHex,
    hexToPoint,
    representation: bn128.representation,
    bytes: bn128.bytes,
    zero: bn128.zero,
    curve: bn128.curve,

    // Commitments
    randomCommit,
    commit,
    difference,
    openingToJson,
    parseOpening,

    // ECIES
    encrypt: ecies.encrypt,
    decrypt: ecies.decrypt,
    generateKeypair: ecies.generateKeypair,

    // ECDSA (secp256k1) for mandate signing
    ecdsa: {
        generateKeypair: keys.generateKeypair,
        sign: keys.sign,
        verify: keys.verify,
        hashJSON: keys.hashJSON,
    },

    // Mandate construction
    mandate: {
        buildOpenCheckoutMandate: mandate.buildOpenCheckoutMandate,
        buildClosedCheckoutMandate: mandate.buildClosedCheckoutMandate,
        hashMandate: mandate.hashMandate,
        isExpired: mandate.isExpired,
    },
};

module.exports = ZKP;
