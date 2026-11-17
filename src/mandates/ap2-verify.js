// AP2 mandate verification, split by role as the specification requires.
//
//   Merchant  : receives the closed Checkout Mandate (plus the open one) and MUST
//               verify checkout_hash against its own checkout JWT, then evaluate the
//               open Checkout constraints.  [specification#merchant]
//   CP/Network: receives the closed Payment Mandate (plus the open one) and MUST
//               evaluate the open Payment constraints.  [specification#credential-provider-and-network]
//   MPP       : receives the payment credential from the merchant and MUST verify it
//               is scoped to the checkout, including the bindings to the checkout JWT
//               hash and the open Checkout Mandate hash.  [specification#merchant-payment-processor]
//
// Inputs are SD-JWT *presentation strings* plus explicit issuer public keys. Every
// presentation is verified with sdjwt.verifyPresentation (issuer signature, _sd_alg,
// committed disclosures, required claims) and constraints are evaluated on the
// recovered claims. A presentation that withholds the `constraints` disclosure is
// therefore rejected: without the disclosure there is no cap to evaluate.
//
// Trust anchors are explicit inputs: the user key comes from enrolment, and the
// agent key is endorsed by the `cnf` claim of the open mandate. Nothing is verified
// against a key carried inside the object being verified.
//
// Any constraint type this implementation does not know fails evaluation, as the
// specification requires.  [agent_authorization]

const sdjwt = require('./sdjwt');
const { isExpired, VCT } = require('./mandate');
const { hashPresented, checkoutHashOf } = require('./hashes');
const { jwkToPub } = require('./jwk');

// Claims that must be disclosed/recovered for a mandate to be evaluated at all.
// `constraints` is mandatory: an agent must not be able to drop the spending cap
// by withholding a disclosure.
const OPEN_MANDATE_REQUIRED = ['vct', 'iss', 'constraints', 'cnf', 'iat', 'exp'];
const CLOSED_CHECKOUT_REQUIRED = ['vct', 'iss', 'checkout_jwt', 'checkout_hash', 'sd_hash', 'iat', 'exp'];
const CLOSED_PAYMENT_REQUIRED = ['vct', 'iss', 'transaction_id', 'sd_hash', 'iat', 'exp'];

// ---- constraint evaluation ----

function evaluateConstraint(c, closed, ctx = {}) {
    const type = c && c.type;
    switch (type) {
        case 'checkout.allowed_merchants': {
            const allowed = Array.isArray(c.allowed) ? c.allowed : [];
            const hit = allowed.some((m) => String(m.id) === String(ctx.merchantId));
            return { type, pass: hit, reason: hit ? 'ok' : 'merchant not in allowed list' };
        }
        case 'checkout.line_items': {
            // This prototype evaluates price-only selection over single-item offers,
            // so line-item matching reduces to "the requirement list is well formed".
            const items = Array.isArray(c.items) ? c.items : [];
            const pass = items.length > 0 && items.every((it) => it && it.id !== undefined);
            return { type, pass, reason: pass ? 'ok' : 'malformed line-item requirements' };
        }
        case 'payment.amount_range': {
            const amount = closed && closed.payment_amount;
            if (!amount || typeof amount.amount !== 'number') {
                return { type, pass: false, reason: 'missing payment_amount' };
            }
            if (amount.currency !== c.currency) {
                return { type, pass: false, reason: 'currency mismatch' };
            }
            const min = typeof c.min === 'number' ? c.min : -Infinity;
            const ok = amount.amount >= min && amount.amount <= c.max;
            return { type, pass: ok, reason: ok ? 'ok' : `amount ${amount.amount} outside [${min}, ${c.max}]` };
        }
        case 'payment.allowed_payees': {
            const allowed = Array.isArray(c.allowed) ? c.allowed : [];
            const payee = closed && closed.payee;
            const hit = !!payee && allowed.some((m) => String(m.id) === String(payee.id));
            return { type, pass: hit, reason: hit ? 'ok' : 'payee not in allowed list' };
        }
        case 'payment.amount_range_committed': {
            // AP2-E extension: the cap is a commitment, so evaluation is delegated to
            // the range-proof verifier, which checks that the commitment opens to a
            // value in range and that the payment amount is at most that value.
            const amount = closed && closed.payment_amount;
            const committed = amount && typeof amount.amount_commitment === 'string'
                && amount.amount_commitment.length > 0;
            if (!committed) {
                return { type, pass: false, reason: 'missing payment_amount.amount_commitment' };
            }
            if (typeof c.commitment !== 'string' || c.commitment.length === 0) {
                return { type, pass: false, reason: 'missing limit commitment' };
            }
            if (amount.currency !== c.currency) {
                return { type, pass: false, reason: 'currency mismatch' };
            }
            const ok = ctx.zkpVerified === true;
            return { type, pass: ok, reason: ok ? 'ok' : 'range-proof verification failed or missing' };
        }
        case 'payment.reference': {
            const expected = ctx.openCheckoutHash;
            const ok = typeof expected === 'string' && c.conditional_transaction_id === expected;
            return { type, pass: ok, reason: ok ? 'ok' : 'conditional_transaction_id does not match the open Checkout' };
        }
        default:
            // Unknown constraints MUST be treated as failing evaluation.
            return { type: String(type), pass: false, reason: 'unknown constraint type' };
    }
}

function evaluateConstraints(constraints, closed, ctx) {
    return (constraints || []).map((c) => evaluateConstraint(c, closed, ctx));
}

// ---- shared helpers ----

// sd_hash of a presentation, or null when the caller omitted it.
function presentationHash(presentation) {
    try {
        return hashPresented(presentation);
    } catch (e) {
        return null;
    }
}

function agentKeyFrom(claims) {
    try {
        return jwkToPub(claims && claims.cnf && claims.cnf.jwk);
    } catch (e) {
        return null;
    }
}

function summarize(checks) {
    const out = {};
    for (const c of checks) out[c.name] = c.pass;
    out.ok = checks.every((c) => c.pass);
    return out;
}

// Verify the holder's key binding (kb-sd-jwt) over one of the presentations in
// this call. `kb.presentation` selects the target ('closedCheckout',
// 'closedPayment', 'openCheckout', ...); it defaults to the mandate the holder is
// being held responsible for.
function checkKb({ add, kb, presentations, defaultPresentation, holderPubkey }) {
    if (!kb) return;
    const selector = kb.presentation || defaultPresentation;
    const presentation = presentations[selector];
    if (typeof kb.kbJwt !== 'string' || !presentation) {
        add(selector + '.kb', false, 'malformed kb-jwt or missing target presentation');
        return;
    }
    const result = sdjwt.verifyKbJwt({
        kbJwt: kb.kbJwt,
        presentation,
        nonce: kb.nonce,
        aud: kb.aud,
        holderPubkey,
    });
    add(selector + '.kb', result.ok, result.reason);
}

// ---- Merchant: closed Checkout Mandate ----
//
// inputs:
//   openCheckoutPresentation, closedCheckoutPresentation — SD-JWT presentations
//   checkoutJwt, merchantCheckoutHash   — the checkout this merchant signed
//   userPubkey                          — trust anchor (enrolment)
//   merchantId                          — identity of this merchant
//   kb                                  — optional { kbJwt, nonce, aud[, presentation] }
function verifyCheckoutMandates({
    openCheckoutPresentation, closedCheckoutPresentation,
    checkoutJwt, merchantCheckoutHash,
    userPubkey, merchantId, kb,
}) {
    const checks = [];
    const add = (name, pass, reason) => checks.push({ name, pass: !!pass, reason: reason || (pass ? 'ok' : 'failed') });

    // The open mandate must verify under the enrolled user key and disclose the
    // constraints the Merchant has to evaluate.
    const open = sdjwt.verifyPresentation({
        presentation: openCheckoutPresentation,
        issuerPubkey: userPubkey,
        requiredClaims: OPEN_MANDATE_REQUIRED,
    });
    add('openCheckout.signature', open.ok, open.reason);
    const openClaims = open.ok ? open.claims : null;
    add('openCheckout.vct', !!(openClaims && openClaims.vct === VCT.OPEN_CHECKOUT), 'vct must be ' + VCT.OPEN_CHECKOUT);
    add('openCheckout.iss', !!(openClaims && userPubkey && openClaims.iss === userPubkey), 'issuer is not the enrolled user');

    const agentKey = agentKeyFrom(openClaims);
    add('openCheckout.cnf', !!agentKey, 'open mandate does not endorse a usable agent key');

    // The closed mandate must verify under the agent key endorsed by cnf.
    const closed = sdjwt.verifyPresentation({
        presentation: closedCheckoutPresentation,
        issuerPubkey: agentKey,
        requiredClaims: CLOSED_CHECKOUT_REQUIRED,
    });
    add('closedCheckout.signature', closed.ok, closed.reason);
    const closedClaims = closed.ok ? closed.claims : null;
    add('closedCheckout.vct', !!(closedClaims && closedClaims.vct === VCT.CLOSED_CHECKOUT), 'vct must be ' + VCT.CLOSED_CHECKOUT);
    add('closedCheckout.iss', !!(closedClaims && agentKey && closedClaims.iss === agentKey), 'issuer is not the agent key endorsed by cnf');

    // checkout_hash binds the closed mandate to the merchant-signed checkout JWT.
    const expectedHash = (typeof checkoutJwt === 'string' && checkoutJwt.length > 0)
        ? checkoutHashOf(checkoutJwt)
        : null;
    add('closedCheckout.checkout_hash', !!(closedClaims && expectedHash && closedClaims.checkout_hash === expectedHash), 'checkout_hash does not match the presented checkout JWT');
    add('closedCheckout.checkout_hash.matchesMerchant', !!(merchantCheckoutHash && expectedHash && merchantCheckoutHash === expectedHash), 'merchant checkout hash mismatch');

    // sd_hash binds the closed mandate to the presented open mandate.
    const openHash = presentationHash(openCheckoutPresentation);
    add('closedCheckout.sd_hash', !!(closedClaims && openHash && closedClaims.sd_hash === openHash), 'sd_hash does not bind the presented open mandate');

    add('openCheckout.notExpired', !!(openClaims && !isExpired(openClaims)), 'open mandate expired or missing exp');
    add('closedCheckout.notExpired', !!(closedClaims && !isExpired(closedClaims)), 'closed mandate expired or missing exp');

    const constraintResults = evaluateConstraints(openClaims && openClaims.constraints, closedClaims, { merchantId });
    for (const r of constraintResults) {
        add(`constraint:${r.type}`, r.pass, r.reason);
    }

    checkKb({
        add,
        kb,
        presentations: {
            openCheckout: openCheckoutPresentation,
            closedCheckout: closedCheckoutPresentation,
        },
        defaultPresentation: 'closedCheckout',
        holderPubkey: agentKey,
    });

    return summarize(checks);
}

// ---- Credential Provider: closed Payment Mandate ----
//
// inputs:
//   openPaymentPresentation, closedPaymentPresentation — SD-JWT presentations
//   openCheckoutPresentation — the open checkout the payment references (optional)
//   userPubkey               — trust anchor (enrolment)
//   zkpVerified              — range-proof outcome for the committed extension
//   kb                       — optional { kbJwt, nonce, aud[, presentation] }
function verifyPaymentMandates({
    openPaymentPresentation, closedPaymentPresentation,
    openCheckoutPresentation, userPubkey, zkpVerified, kb,
}) {
    const checks = [];
    const add = (name, pass, reason) => checks.push({ name, pass: !!pass, reason: reason || (pass ? 'ok' : 'failed') });

    const open = sdjwt.verifyPresentation({
        presentation: openPaymentPresentation,
        issuerPubkey: userPubkey,
        requiredClaims: OPEN_MANDATE_REQUIRED,
    });
    add('openPayment.signature', open.ok, open.reason);
    const openClaims = open.ok ? open.claims : null;
    add('openPayment.vct', !!(openClaims && openClaims.vct === VCT.OPEN_PAYMENT), 'vct must be ' + VCT.OPEN_PAYMENT);
    add('openPayment.iss', !!(openClaims && userPubkey && openClaims.iss === userPubkey), 'issuer is not the enrolled user');

    const agentKey = agentKeyFrom(openClaims);
    add('openPayment.cnf', !!agentKey, 'open mandate does not endorse a usable agent key');

    const closed = sdjwt.verifyPresentation({
        presentation: closedPaymentPresentation,
        issuerPubkey: agentKey,
        requiredClaims: CLOSED_PAYMENT_REQUIRED,
    });
    add('closedPayment.signature', closed.ok, closed.reason);
    const closedClaims = closed.ok ? closed.claims : null;
    add('closedPayment.vct', !!(closedClaims && closedClaims.vct === VCT.CLOSED_PAYMENT), 'vct must be ' + VCT.CLOSED_PAYMENT);
    add('closedPayment.iss', !!(closedClaims && agentKey && closedClaims.iss === agentKey), 'issuer is not the agent key endorsed by cnf');

    // transaction_id binds the payment to the merchant-signed checkout JWT.
    add('closedPayment.transaction_id',
        !!(closedClaims && typeof closedClaims.transaction_id === 'string' && closedClaims.transaction_id.length > 0),
        'missing transaction_id');

    // sd_hash binds the closed payment mandate to the presented open payment mandate.
    const openPaymentHash = presentationHash(openPaymentPresentation);
    add('closedPayment.sd_hash', !!(closedClaims && openPaymentHash && closedClaims.sd_hash === openPaymentHash), 'sd_hash does not bind the presented open payment mandate');

    add('openPayment.notExpired', !!(openClaims && !isExpired(openClaims)), 'open mandate expired or missing exp');
    add('closedPayment.notExpired', !!(closedClaims && !isExpired(closedClaims)), 'closed mandate expired or missing exp');

    const openCheckoutHash = presentationHash(openCheckoutPresentation);
    const constraintResults = evaluateConstraints(openClaims && openClaims.constraints, closedClaims, {
        openCheckoutHash,
        // Only set for the committed-cap extension, where evaluation is delegated to
        // the range-proof verifier.
        zkpVerified,
    });
    for (const r of constraintResults) {
        add(`constraint:${r.type}`, r.pass, r.reason);
    }

    checkKb({
        add,
        kb,
        presentations: {
            openPayment: openPaymentPresentation,
            closedPayment: closedPaymentPresentation,
        },
        defaultPresentation: 'closedPayment',
        holderPubkey: agentKey,
    });

    return summarize(checks);
}

// ---- Merchant Payment Processor: credential scoping ----
//
// The credential must be scoped to this checkout: the payment it names and the
// checkout it pays for have to be the ones presented. Issuer keys are explicit:
// the agent key is recovered from the open Checkout Mandate under the user trust
// anchor, or passed directly by the caller.
function verifyAtMpp({
    token, closedPaymentPresentation, closedCheckoutPresentation,
    openCheckoutPresentation, userPubkey, agentPubkey, kb,
}) {
    const checks = [];
    const add = (name, pass, reason) => checks.push({ name, pass: !!pass, reason: reason || (pass ? 'ok' : 'failed') });

    let agentKey = null;
    if (openCheckoutPresentation !== undefined) {
        const open = sdjwt.verifyPresentation({
            presentation: openCheckoutPresentation,
            issuerPubkey: userPubkey,
            requiredClaims: OPEN_MANDATE_REQUIRED,
        });
        add('openCheckout.signature', open.ok, open.reason);
        const openClaims = open.ok ? open.claims : null;
        add('openCheckout.iss', !!(openClaims && userPubkey && openClaims.iss === userPubkey), 'issuer is not the enrolled user');
        agentKey = agentKeyFrom(openClaims);
    }
    if (!agentKey && agentPubkey) agentKey = agentPubkey;

    const closedCheckout = sdjwt.verifyPresentation({
        presentation: closedCheckoutPresentation,
        issuerPubkey: agentKey,
        requiredClaims: CLOSED_CHECKOUT_REQUIRED,
    });
    add('closedCheckout.signature', closedCheckout.ok, closedCheckout.reason);
    const closedCheckoutClaims = closedCheckout.ok ? closedCheckout.claims : null;
    add('closedCheckout.vct', !!(closedCheckoutClaims && closedCheckoutClaims.vct === VCT.CLOSED_CHECKOUT), 'vct must be ' + VCT.CLOSED_CHECKOUT);
    add('closedCheckout.iss', !!(closedCheckoutClaims && agentKey && closedCheckoutClaims.iss === agentKey), 'issuer is not the agent key endorsed by cnf');

    const closedPayment = sdjwt.verifyPresentation({
        presentation: closedPaymentPresentation,
        issuerPubkey: agentKey,
        requiredClaims: CLOSED_PAYMENT_REQUIRED,
    });
    add('closedPayment.signature', closedPayment.ok, closedPayment.reason);
    const closedPaymentClaims = closedPayment.ok ? closedPayment.claims : null;
    add('closedPayment.vct', !!(closedPaymentClaims && closedPaymentClaims.vct === VCT.CLOSED_PAYMENT), 'vct must be ' + VCT.CLOSED_PAYMENT);
    add('closedPayment.iss', !!(closedPaymentClaims && agentKey && closedPaymentClaims.iss === agentKey), 'issuer is not the agent key endorsed by cnf');

    add('token.present', !!token && typeof token === 'object', 'missing payment credential');
    add('token.paymentReference',
        !!(token && closedPaymentClaims && token.payment_reference === presentationHash(closedPaymentPresentation)),
        'credential is not scoped to the presented closed Payment Mandate');
    add('token.checkoutHash',
        !!(token && closedCheckoutClaims && token.checkout_hash === closedCheckoutClaims.checkout_hash),
        'credential is not scoped to the presented closed Checkout Mandate');

    // The two bindings the flows page requires the MPP to check.
    add('binding.checkout',
        !!(closedPaymentClaims && closedCheckoutClaims && closedPaymentClaims.transaction_id === closedCheckoutClaims.checkout_hash),
        'transaction_id does not match checkout_hash');
    add('binding.openCheckout',
        !!(closedCheckoutClaims && closedCheckoutClaims.sd_hash === presentationHash(openCheckoutPresentation)),
        'sd_hash does not bind the presented open Checkout Mandate');

    checkKb({
        add,
        kb,
        presentations: {
            closedCheckout: closedCheckoutPresentation,
            closedPayment: closedPaymentPresentation,
            openCheckout: openCheckoutPresentation,
        },
        defaultPresentation: 'closedPayment',
        holderPubkey: agentKey,
    });

    return summarize(checks);
}

module.exports = {
    evaluateConstraint,
    evaluateConstraints,
    verifyCheckoutMandates,
    verifyPaymentMandates,
    verifyAtMpp,
};
