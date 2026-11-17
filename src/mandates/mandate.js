// AP2 mandates and receipts — field-for-field following the AP2 v0.2 specification
// (https://ap2-protocol.org/ap2/checkout_mandate/, /payment_mandate/, /flows/).
//
// Encoding: AP2 secures mandates as SD-JWTs (RFC 9901) with a Key-Binding JWT.
// This module issues them with the local ES256K primitives in ./sdjwt.js:
//   * each mandate is signed by its issuer as a JWS compact string (the `sdjwt`
//     field of the returned handle) and travels as an SD-JWT presentation;
//   * the issuer's compressed public key stays in the `iss` claim, as before;
//   * `checkout_hash`, `sd_hash` and a receipt's `reference` hash the exact wire
//     artefacts (checkout JWS / presentation), never a canonical-JSON rendering.
// Every claim name, type, required-ness and enum below matches the specification.
//
// Human Not Present: the User signs the open Checkout and open Payment Mandates
// before any cart exists; the Agent signs the closed Checkout and closed Payment
// Mandates when it commits to a checkout. Builders therefore take the issuer's
// secret key (`userSk` / `agentSk` / `sk` for receipts) in addition to the
// public key that is written into the signed claims.

const keys = require('./keys');
const sdjwt = require('./sdjwt');
const { pubToJwk } = require('./jwk');
const { hashPresented, checkoutHashOf } = require('./hashes');

// `vct` values, including the mandatory version suffix.
const VCT = {
    OPEN_CHECKOUT: 'mandate.checkout.open.1',
    CLOSED_CHECKOUT: 'mandate.checkout.1',
    OPEN_PAYMENT: 'mandate.payment.open.1',
    CLOSED_PAYMENT: 'mandate.payment.1',
};

// Selectively disclosable claim names per mandate type (fixed by the contract).
const DISCLOSABLE = {
    OPEN_CHECKOUT: ['constraints'],
    OPEN_PAYMENT: ['constraints'],
    CLOSED_CHECKOUT: [],
    CLOSED_PAYMENT: [],
    CLOSED_PAYMENT_COMMITTED: ['payment_amount'],
};

// AP2 timestamps are integers (Unix epoch seconds).
const nowSec = () => Math.floor(Date.now() / 1000);

// A Merchant object as used by `payee` and `allowed` arrays.
function merchant({ id, name, website }) {
    return { id, name, website };
}

// ---- issuance helpers ----

// Compressed public key hex for a private key, used to keep `iss` and the
// signing key in sync.
function publicKeyOf(skHex) {
    return keys.fromPrivate(skHex).getPublic(true, 'hex');
}

// Resolve the signer of a mandate/receipt. The secret key is required because
// SD-JWT issuance signs at build time; a supplied public key must match it.
function resolveSigner({ skHex, pubkey, label }) {
    if (typeof skHex !== 'string' || skHex.length === 0) {
        throw new Error(label + ': issuer secret key is required to sign the SD-JWT');
    }
    const derived = publicKeyOf(skHex);
    if (pubkey !== undefined && pubkey !== null && pubkey !== derived) {
        throw new Error(label + ': issuer public key does not match the secret key');
    }
    return { skHex, pubkey: derived };
}

// Wrap an issued SD-JWT in the handle every builder returns. `present(names?)`
// emits a presentation string; by default it discloses every disclosable claim.
function makeSdJwtHandle({ claims, disclosable, skHex }) {
    const issued = sdjwt.issueSdJwt({ claims, disclosable, skHex });
    const disclosureByName = new Map();
    for (const disclosure of issued.disclosures) {
        const [, name] = sdjwt.parseDisclosure(disclosure);
        disclosureByName.set(name, disclosure);
    }
    return {
        vct: claims.vct,
        sdjwt: issued.sdjwt,
        disclosures: issued.disclosures,
        claims,
        present(names) {
            let selected = issued.disclosures;
            if (names !== undefined) {
                if (!Array.isArray(names)) throw new TypeError('present(names) expects an array of claim names');
                selected = names.map((name) => {
                    if (!disclosureByName.has(name)) {
                        throw new Error('claim is not selectively disclosable: ' + name);
                    }
                    return disclosureByName.get(name);
                });
            }
            return sdjwt.present({ sdjwt: issued.sdjwt, disclosures: selected });
        },
    };
}

// Receipts are plain JWTs (no selective disclosure), so they are signed without
// `_sd`/`_sd_alg`; the handle exposes the same shape as mandate handles with an
// empty disclosure list.
function makeJwsHandle({ claims, skHex }) {
    const jwt = sdjwt.signJws(claims, skHex);
    return {
        vct: claims.vct,
        sdjwt: jwt,
        disclosures: [],
        claims,
        present() {
            return sdjwt.present({ sdjwt: jwt, disclosures: [] });
        },
    };
}

// ---- open Checkout Mandate (User -> Agent) ----
// Constraints available on the checkout side: checkout.allowed_merchants,
// checkout.line_items. Note that AP2 defines no checkout-side amount constraint;
// the spending cap lives in the open Payment Mandate.
function buildOpenCheckoutMandate({
    userPubkey, userSk, agentPubkey, allowedMerchants, lineItems, expiresInSec = 3600,
}) {
    const signer = resolveSigner({ skHex: userSk, pubkey: userPubkey, label: 'open Checkout Mandate' });
    if (!agentPubkey) throw new Error('open Checkout Mandate: agentPubkey is required for cnf');
    const constraints = [];
    if (Array.isArray(allowedMerchants) && allowedMerchants.length > 0) {
        constraints.push({ type: 'checkout.allowed_merchants', allowed: allowedMerchants });
    }
    if (Array.isArray(lineItems) && lineItems.length > 0) {
        constraints.push({ type: 'checkout.line_items', items: lineItems });
    }
    const iat = nowSec();
    const claims = {
        vct: VCT.OPEN_CHECKOUT,
        iss: signer.pubkey,
        constraints,
        // `cnf` is REQUIRED while the mandate is open: it sender-constrains the
        // closed mandates to the Agent's key.
        cnf: { jwk: pubToJwk(agentPubkey) },
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({ claims, disclosable: DISCLOSABLE.OPEN_CHECKOUT, skHex: signer.skHex });
}

// ---- open Payment Mandate (User -> Agent) ----
// Carries the spending cap (`payment.amount_range`), the payee allowlist, and the
// reference that pins this mandate to the open Checkout it was approved with.
function buildOpenPaymentMandate({
    userPubkey, userSk, agentPubkey, currency, maxAmount, minAmount = 0,
    allowedPayees, openCheckout, expiresInSec = 3600,
}) {
    const signer = resolveSigner({ skHex: userSk, pubkey: userPubkey, label: 'open Payment Mandate' });
    if (!agentPubkey) throw new Error('open Payment Mandate: agentPubkey is required for cnf');
    const iat = nowSec();
    const claims = {
        vct: VCT.OPEN_PAYMENT,
        iss: signer.pubkey,
        constraints: [
            { type: 'payment.amount_range', currency, max: maxAmount, min: minAmount },
            { type: 'payment.allowed_payees', allowed: allowedPayees },
            { type: 'payment.reference', conditional_transaction_id: hashPresented(openCheckout) },
        ],
        cnf: { jwk: pubToJwk(agentPubkey) },
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({ claims, disclosable: DISCLOSABLE.OPEN_PAYMENT, skHex: signer.skHex });
}

// ---- closed Checkout Mandate (Agent -> Merchant) ----
function buildClosedCheckoutMandate({
    agentPubkey, agentSk, checkoutJwt, openCheckout, expiresInSec = 300,
}) {
    const signer = resolveSigner({ skHex: agentSk, pubkey: agentPubkey, label: 'closed Checkout Mandate' });
    const iat = nowSec();
    const claims = {
        vct: VCT.CLOSED_CHECKOUT,
        iss: signer.pubkey,
        checkout_jwt: checkoutJwt,
        checkout_hash: checkoutHashOf(checkoutJwt),
        sd_hash: hashPresented(openCheckout),
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({ claims, disclosable: DISCLOSABLE.CLOSED_CHECKOUT, skHex: signer.skHex });
}

// ---- closed Payment Mandate (Agent -> Credential Provider) ----
function buildClosedPaymentMandate({
    agentPubkey, agentSk, checkoutJwt, payee, paymentAmount, paymentInstrument,
    openPayment, expiresInSec = 300,
}) {
    const signer = resolveSigner({ skHex: agentSk, pubkey: agentPubkey, label: 'closed Payment Mandate' });
    const iat = nowSec();
    const claims = {
        vct: VCT.CLOSED_PAYMENT,
        iss: signer.pubkey,
        // transaction_id and the closed Checkout's checkout_hash are the same value:
        // the hash of the merchant-signed checkout JWT.
        transaction_id: checkoutHashOf(checkoutJwt),
        payee,
        payment_amount: paymentAmount,
        payment_instrument: paymentInstrument,
        sd_hash: hashPresented(openPayment),
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({ claims, disclosable: DISCLOSABLE.CLOSED_PAYMENT, skHex: signer.skHex });
}

// ---- open Payment Mandate with a committed spending cap (AP2-E) ----
//
// AP2's `payment.amount_range` requires the cap in plaintext. The range-proof
// prototype hides it behind a Pedersen commitment, which AP2 supports through its
// documented extension point: "To define a new constraint, the following MUST be
// specified: a uniquely defined type; a schema, including which fields are
// selectively disclosable; the evaluation algorithm."  [specification]
//
// This constraint type is therefore an AP2 extension, not a departure from it:
//   type: payment.amount_range_committed
//   currency: ISO 4217 code
//   commitment: Pedersen commitment to the cap
//   sealed: ECIES-sealed opening of that commitment, for the Agent
// The evaluation algorithm is "verify that `commitment` opens to a value in
// [0, 2^l) and that the closed Payment Mandate's amount_commitment is at most that
// value", carried out by the range-proof verifier.
function buildOpenPaymentMandateCommitted({
    userPubkey, userSk, agentPubkey, currency, limitCommitment, sealedLimit,
    allowedPayees, openCheckout, expiresInSec = 3600,
}) {
    const signer = resolveSigner({ skHex: userSk, pubkey: userPubkey, label: 'open Payment Mandate' });
    if (!agentPubkey) throw new Error('open Payment Mandate: agentPubkey is required for cnf');
    const iat = nowSec();
    const claims = {
        vct: VCT.OPEN_PAYMENT,
        iss: signer.pubkey,
        constraints: [
            {
                type: 'payment.amount_range_committed',
                currency,
                commitment: limitCommitment,
                sealed: sealedLimit,
            },
            { type: 'payment.allowed_payees', allowed: allowedPayees },
            { type: 'payment.reference', conditional_transaction_id: hashPresented(openCheckout) },
        ],
        cnf: { jwk: pubToJwk(agentPubkey) },
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({ claims, disclosable: DISCLOSABLE.OPEN_PAYMENT, skHex: signer.skHex });
}

// ---- closed Payment Mandate with a committed amount (AP2-E) ----
// `payment_amount.amount` becomes a commitment; the range proofs that relate it to
// the committed cap travel alongside the mandate as evidence. The committed amount
// is the only selectively disclosable claim in a closed mandate.
function buildClosedPaymentMandateCommitted({
    agentPubkey, agentSk, checkoutJwt, payee, amountCommitment, currency,
    paymentInstrument, openPayment, evidence, expiresInSec = 300,
}) {
    const signer = resolveSigner({ skHex: agentSk, pubkey: agentPubkey, label: 'closed Payment Mandate' });
    const iat = nowSec();
    const claims = {
        vct: VCT.CLOSED_PAYMENT,
        iss: signer.pubkey,
        transaction_id: checkoutHashOf(checkoutJwt),
        payee,
        payment_amount: { amount_commitment: amountCommitment, currency },
        payment_instrument: paymentInstrument,
        sd_hash: hashPresented(openPayment),
        evidence: evidence || null,
        iat,
        exp: iat + expiresInSec,
    };
    return makeSdJwtHandle({
        claims,
        disclosable: DISCLOSABLE.CLOSED_PAYMENT_COMMITTED,
        skHex: signer.skHex,
    });
}

// ---- Receipts ----
// Checkout Receipt: issued by the Merchant once it accepts or rejects the closed
// Checkout Mandate. `reference` is the hash of that closed mandate's presentation.
function buildCheckoutReceipt({
    iss, sk, status, reference, orderId, error, errorDescription,
}) {
    const signer = resolveSigner({ skHex: sk, pubkey: iss, label: 'Checkout Receipt' });
    const claims = { status, iss: signer.pubkey, iat: nowSec(), reference };
    if (status === 'Error') {
        claims.error = error || 'invalid_mandate';
        claims.error_description = errorDescription || 'Mandate verification failed';
    } else {
        claims.order_id = orderId || `order_${Math.random().toString(36).slice(2, 10)}`;
    }
    return makeJwsHandle({ claims, skHex: signer.skHex });
}

// Payment Receipt: issued by the Merchant Payment Processor. `payment_id` is always
// required; the PSP confirmation id is present only on success.
function buildPaymentReceipt({
    iss, sk, status, reference, paymentId, pspConfirmationId, error, errorDescription,
}) {
    const signer = resolveSigner({ skHex: sk, pubkey: iss, label: 'Payment Receipt' });
    const claims = { status, iss: signer.pubkey, iat: nowSec(), reference, payment_id: paymentId };
    if (status === 'Error') {
        claims.error = error || 'invalid_mandate';
        claims.error_description = errorDescription || 'Payment verification failed';
    } else {
        claims.psp_confirmation_id = pspConfirmationId || `psp_${Math.random().toString(36).slice(2, 10)}`;
    }
    return makeJwsHandle({ claims, skHex: signer.skHex });
}

// ---- Helpers shared by every role ----

// The AP2 mandate hash is the sd_hash of the mandate's presentation: the issuer
// signs a JWS, and every later reference hashes the artefact actually presented.
function hashMandate(mandate) {
    return hashPresented(mandate);
}

// Emit a presentation for a mandate handle (the handle's own `present` is the
// primary API; this is the module-level convenience the contract lists).
function presentMandate(handle, names) {
    if (!handle || typeof handle.present !== 'function') {
        throw new Error('presentMandate expects an SD-JWT mandate handle');
    }
    return handle.present(names);
}

// AP2 `exp` is an optional integer timestamp. We fail closed: a mandate without a
// usable `exp` is treated as expired rather than accepted. Accepts a handle or a
// recovered claims object.
function isExpired(m) {
    const claims = m && m.claims ? m.claims : m;
    if (!claims || typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) return true;
    return claims.exp < nowSec();
}

module.exports = {
    VCT,
    DISCLOSABLE,
    merchant,
    nowSec,
    buildOpenCheckoutMandate,
    buildOpenPaymentMandate,
    buildOpenPaymentMandateCommitted,
    buildClosedCheckoutMandate,
    buildClosedPaymentMandate,
    buildClosedPaymentMandateCommitted,
    buildCheckoutReceipt,
    buildPaymentReceipt,
    hashMandate,
    presentMandate,
    isExpired,
    // hashing helpers, re-exported so roles do not import hashes directly
    checkoutHashOf,
    hashPresented,
};
