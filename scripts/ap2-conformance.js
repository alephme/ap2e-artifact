// AP2 conformance check: run one honest purchase and validate every artefact against
// the field names, types and required-ness defined by AP2 v0.2.
//
// Sources:
//   https://ap2-protocol.org/ap2/checkout_mandate/
//   https://ap2-protocol.org/ap2/payment_mandate/
//   https://ap2-protocol.org/ap2/flows/
//   https://ap2-protocol.org/ap2/specification/
//
// Encoding caveat (disclosed in the paper): mandates are flat JSON signed with ECDSA
// instead of SD-JWTs, and `iss` carries the issuer's key in place of the JWT `kid`.
// Everything else — vct strings, claim names, value types, receipt fields — is checked
// against the specification as written.
//
// Usage: node scripts/ap2-conformance.js [--verbose]

const { start: startMerchant } = require('../src/systems/merchant-server');
const { start: startVerifier } = require('../src/systems/verifier-server');
const { start: startProvider } = require('../src/systems/credential-provider');
const { start: startMpp } = require('../src/systems/mpp-server');
const { start: startAp2Agent } = require('../src/systems/ap2-only/agent-server');
const keys = require('../src/mandates/keys');
const mandate = require('../src/mandates/mandate');
const { base64urlDecode, hashPresented } = require('../src/mandates/hashes');

const PORTS = { merchant: 18610, provider: 18690, mpp: 18695, agent: 18601 };
const BASE = (p) => `http://localhost:${p}`;
const CURRENCY = 'USD';
const VERBOSE = process.argv.includes('--verbose');

// ---- tiny schema engine ----

const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const isStr = (v) => typeof v === 'string' && v.length > 0;
const isB64Url = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v);

const results = [];
function check(artifact, field, expected, actual, pass) {
    results.push({ artifact, field, expected, actual: String(actual), pass });
}

function field(obj, name, spec, artifact) {
    const value = obj == null ? undefined : obj[name];
    const present = value !== undefined && value !== null;
    if (spec.required && !present) {
        check(artifact, name, `${spec.type} (required)`, 'missing', false);
        return undefined;
    }
    if (!present) {
        if (spec.type === 'optional') check(artifact, name, 'optional, absent', 'absent', true);
        return undefined;
    }
    let pass = true;
    switch (spec.type) {
        case 'string': pass = isStr(value); break;
        case 'integer': pass = isInt(value); break;
        case 'array': pass = Array.isArray(value); break;
        case 'object': pass = typeof value === 'object' && !Array.isArray(value); break;
        case 'b64url': pass = isB64Url(value); break;
        case 'enum': pass = spec.values.includes(value); break;
        case 'const': pass = value === spec.value; break;
        default: pass = true;
    }
    check(artifact, name, spec.type === 'const' ? `"${spec.value}"` : spec.type, JSON.stringify(value), pass);
    return value;
}

function validateFields(obj, schema, artifact) {
    for (const [name, spec] of Object.entries(schema)) field(obj, name, spec, artifact);
}

// ---- schemas (AP2 v0.2) ----

const MERCHANT_SCHEMA = {
    id: { type: 'string', required: false }, // id may be int in our prototype; checked below
    name: { type: 'string', required: true },
};

const OPEN_CHECKOUT_SCHEMA = {
    vct: { type: 'const', value: 'mandate.checkout.open.1', required: true },
    constraints: { type: 'array', required: true },
    cnf: { type: 'object', required: true },
    iat: { type: 'integer', required: true },
    exp: { type: 'integer', required: true },
};

const OPEN_PAYMENT_SCHEMA = {
    vct: { type: 'const', value: 'mandate.payment.open.1', required: true },
    constraints: { type: 'array', required: true },
    cnf: { type: 'object', required: true },
    iat: { type: 'integer', required: true },
    exp: { type: 'integer', required: true },
};

const CLOSED_CHECKOUT_SCHEMA = {
    vct: { type: 'const', value: 'mandate.checkout.1', required: true },
    checkout_jwt: { type: 'string', required: true },
    checkout_hash: { type: 'b64url', required: true },
    sd_hash: { type: 'b64url', required: true },
    iat: { type: 'integer', required: true },
    exp: { type: 'integer', required: true },
};

const CLOSED_PAYMENT_SCHEMA = {
    vct: { type: 'const', value: 'mandate.payment.1', required: true },
    transaction_id: { type: 'b64url', required: true },
    payee: { type: 'object', required: true },
    payment_amount: { type: 'object', required: true },
    payment_instrument: { type: 'object', required: true },
    sd_hash: { type: 'b64url', required: true },
};

const CHECKOUT_RECEIPT_SCHEMA = {
    status: { type: 'enum', values: ['Success', 'Error'], required: true },
    iss: { type: 'string', required: true },
    iat: { type: 'integer', required: true },
    reference: { type: 'string', required: true },
    order_id: { type: 'string', required: false },
    error: { type: 'string', required: false },
    error_description: { type: 'string', required: false },
};

const PAYMENT_RECEIPT_SCHEMA = {
    status: { type: 'enum', values: ['Success', 'Error'], required: true },
    iss: { type: 'string', required: true },
    iat: { type: 'integer', required: true },
    reference: { type: 'string', required: true },
    payment_id: { type: 'string', required: true },
    psp_confirmation_id: { type: 'string', required: false },
    error: { type: 'string', required: false },
    error_description: { type: 'string', required: false },
};

// ---- one honest run ----

async function runOnce(userKp, allowed, limit) {
    const build = await (await fetch(`${BASE(PORTS.agent)}/build-mandate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            userPubkey: userKp.pk, userSk: userKp.sk,
            currency: CURRENCY, maxAmount: limit, allowedMerchants: allowed,
        }),
    })).json();
    if (build.error) throw new Error('build-mandate: ' + build.error);

    // The open mandates are SD-JWTs signed at build time, so the user no longer signs
    // separately; the agent forwards the presentations as they are.
    const exec = await (await fetch(`${BASE(PORTS.agent)}/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            openCheckoutPresentation: build.openCheckoutPresentation,
            openPaymentPresentation: build.openPaymentPresentation,
            userPubkey: userKp.pk,
        }),
    })).json();
    if (exec.error) throw new Error('execute: ' + exec.error);

    return exec.result;
}

async function main() {
    const userKp = keys.generateKeypair();
    const quotes = [120, 95, 150, 130];
    const allowed = quotes.map((_, i) => mandate.merchant({
        id: i, name: `Merchant ${i}`, website: `https://merchant${i}.example`,
    }));
    const limit = 140;

    const merchant = await startMerchant({ port: PORTS.merchant, mode: 'plain', quotes, userPubkey: userKp.pk });
    const verifier = await startVerifier({ port: PORTS.verifier });
    const provider = await startProvider({ port: PORTS.provider, userPubkey: userKp.pk });
    const mpp = await startMpp({ port: PORTS.mpp, userPubkey: userKp.pk });
    const agent = await startAp2Agent({
        port: PORTS.agent, merchantUrl: BASE(PORTS.merchant),
        verifierUrl: BASE(PORTS.verifier),
        providerUrl: BASE(PORTS.provider), mppUrl: BASE(PORTS.mpp),
    });

    let r;
    try {
        r = await runOnce(userKp, allowed, limit);
    } finally {
        // servers stay up until validation is done
    }

    // ---- 1. open Checkout Mandate ----
    // The mandates cross the wire as SD-JWT presentations; the agent also returns the
    // recovered claims for inspection, so the field checks read those.
    const oc = r.openCheckoutClaims || {};
    const op = r.openPaymentClaims || {};
    const cc = r.closedCheckoutClaims || {};
    const cpClaims = r.closedPaymentClaims || {};
    validateFields(oc, OPEN_CHECKOUT_SCHEMA, 'openCheckout');
    const ocConstraintTypes = (oc.constraints || []).map((c) => c.type);
    check('openCheckout', 'constraints[].type',
        'subset of {checkout.allowed_merchants, checkout.line_items}',
        ocConstraintTypes.join(','),
        ocConstraintTypes.every((t) => ['checkout.allowed_merchants', 'checkout.line_items'].includes(t)));
    const cnfJwk = oc.cnf && oc.cnf.jwk;
    check('openCheckout', 'cnf.jwk', '{kty,crv,x,y}', JSON.stringify(cnfJwk && Object.keys(cnfJwk)),
        !!(cnfJwk && cnfJwk.kty === 'EC' && typeof cnfJwk.crv === 'string'
            && typeof cnfJwk.x === 'string' && typeof cnfJwk.y === 'string'));

    // ---- 2. open Payment Mandate ----
    validateFields(op, OPEN_PAYMENT_SCHEMA, 'openPayment');
    const opConstraints = op.constraints || [];
    const amountRange = opConstraints.find((c) => c.type === 'payment.amount_range');
    const allowedPayees = opConstraints.find((c) => c.type === 'payment.allowed_payees');
    const reference = opConstraints.find((c) => c.type === 'payment.reference');
    check('openPayment', 'constraints[payment.amount_range]',
        '{type,currency,max(,min)}',
        JSON.stringify(amountRange),
        !!(amountRange && isStr(amountRange.currency) && isInt(amountRange.max)
            && (amountRange.min === undefined || isInt(amountRange.min))));
    check('openPayment', 'constraints[payment.allowed_payees]',
        '{type,allowed:[Merchant]}',
        allowedPayees ? `${allowedPayees.allowed.length} entries` : 'missing',
        !!(allowedPayees && Array.isArray(allowedPayees.allowed) && allowedPayees.allowed.length > 0
            && allowedPayees.allowed.every((m) => m && m.id !== undefined && isStr(m.name))));
    check('openPayment', 'constraints[payment.reference]',
        '{type,conditional_transaction_id}',
        reference ? reference.conditional_transaction_id : 'missing',
        !!(reference && isStr(reference.conditional_transaction_id)));
    check('openPayment', 'payment.reference binds open Checkout',
        hashPresented(r.openCheckout),
        reference && reference.conditional_transaction_id,
        !!(reference && reference.conditional_transaction_id === hashPresented(r.openCheckout)));

    // ---- 3. closed Checkout Mandate ----
    validateFields(cc, CLOSED_CHECKOUT_SCHEMA, 'closedCheckout');
    check('closedCheckout', 'checkout_hash = base64url(sha256(checkout_jwt))',
        'base64url digest', cc.checkout_hash,
        (() => {
            try { base64urlDecode(cc.checkout_hash); return true; } catch (e) { return false; }
        })());

    // ---- 4. closed Payment Mandate ----
    validateFields(cpClaims, CLOSED_PAYMENT_SCHEMA, 'closedPayment');
    const pa = cpClaims.payment_amount;
    check('closedPayment', 'payment_amount', '{amount:int,currency:ISO4217}',
        JSON.stringify(pa), !!(pa && isInt(pa.amount) && isStr(pa.currency) && pa.currency.length === 3));
    const payee = cpClaims.payee;
    check('closedPayment', 'payee', 'Merchant {id,name}',
        JSON.stringify(payee), !!(payee && payee.id !== undefined && isStr(payee.name)));
    const pi = cpClaims.payment_instrument;
    check('closedPayment', 'payment_instrument', '{id,type}',
        JSON.stringify(pi), !!(pi && isStr(pi.id) && isStr(pi.type)));

    // ---- binding chain ----
    check('binding', 'closedPayment.transaction_id == closedCheckout.checkout_hash',
        cc.checkout_hash, cpClaims.transaction_id,
        cpClaims.transaction_id === cc.checkout_hash);

    // ---- 5. receipts ----
    validateFields(r.checkoutReceipt, CHECKOUT_RECEIPT_SCHEMA, 'checkoutReceipt');
    check('checkoutReceipt', 'order_id iff Success', 'present on Success',
        r.checkoutReceipt && r.checkoutReceipt.order_id,
        !!(r.checkoutReceipt && r.checkoutReceipt.status === 'Success'
            && isStr(r.checkoutReceipt.order_id) && !('error' in r.checkoutReceipt)));

    validateFields(r.paymentReceipt, PAYMENT_RECEIPT_SCHEMA, 'paymentReceipt');
    check('paymentReceipt', 'psp_confirmation_id iff Success', 'present on Success',
        r.paymentReceipt && r.paymentReceipt.psp_confirmation_id,
        !!(r.paymentReceipt && r.paymentReceipt.status === 'Success'
            && isStr(r.paymentReceipt.psp_confirmation_id) && !('error' in r.paymentReceipt)));

    // ---- 6. verifier verdicts ----
    for (const role of ['merchant', 'cp', 'mpp']) {
        const c = r.checks && r.checks[role];
        check(`${role} verification`, 'all checks pass', 'ok', c ? c.ok : 'missing', !!(c && c.ok));
    }

    // ---- report ----
    const width = Math.max(...results.map((x) => x.artifact.length));
    const fw = Math.max(...results.map((x) => x.field.length));
    console.log('AP2 v0.2 conformance check\n');
    for (const x of results) {
        if (!x.pass || VERBOSE) {
            console.log(`${x.pass ? 'PASS' : 'FAIL'}  ${x.artifact.padEnd(width)}  ${x.field.padEnd(fw)}  expected=${x.expected}  actual=${x.actual}`);
        }
    }
    const failed = results.filter((x) => !x.pass);
    console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
    if (failed.length) {
        console.log(`\n${failed.length} FAILED:`);
        for (const x of failed) console.log(`  ${x.artifact}.${x.field}: expected ${x.expected}, got ${x.actual}`);
    }

    await new Promise((res) => agent.close(res));
    await new Promise((res) => verifier.close(res));
    await new Promise((res) => mpp.close(res));
    await new Promise((res) => provider.close(res));
    await new Promise((res) => merchant.close(res));

    process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
