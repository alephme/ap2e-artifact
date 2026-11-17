// AP2 specification conformance: the four mandates, the merchant-signed checkout,
// and the two receipts, checked end to end across the three verifying roles.
//
// Roles and trust anchors follow AP2 v0.2 (Human Not Present):
//   User  signs open Checkout + open Payment (SD-JWT, constraints disclosable)
//   Agent signs closed Checkout + closed Payment (key endorsed by cnf) and
//         attaches a kb-sd-jwt when it presents them
//   Merchant verifies the closed Checkout presentation and evaluates the open
//         Checkout constraints on the recovered claims
//   CP verifies the closed Payment presentation and evaluates the open Payment
//         constraints
//   MPP verifies the credential is scoped to the checkout, over presentations
//
// Every mandate crosses the wire as a presentation string; verifiers receive the
// issuer public keys explicitly and never trust a key carried in the artefact.

const test = require('node:test');
const assert = require('node:assert');

const keys = require('../src/mandates/keys');
const sdjwt = require('../src/mandates/sdjwt');
const mandate = require('../src/mandates/mandate');
const verify = require('../src/mandates/ap2-verify');
const { hashPresented, checkoutHashOf } = require('../src/mandates/hashes');

const CURRENCY = 'USD';
const LIMIT = 20000;       // minor units
const NONCE = 'verifier-nonce-1';
const AUD = { merchant: 'merchant.example', cp: 'cp.example', mpp: 'mpp.example' };

// ---- fixtures ----

function makeWorld() {
    const user = keys.generateKeypair();
    const agent = keys.generateKeypair();
    const merchantKp = keys.generateKeypair();

    const merchantObj = { id: 0, name: 'Merchant 0', website: 'https://m0.example' };
    const paymentInstrument = { id: 'pi_1', type: 'card', description: 'test card' };

    // Phase 1a: user issues the open mandates before any cart exists.
    const openCheckout = mandate.buildOpenCheckoutMandate({
        userPubkey: user.pk,
        userSk: user.sk,
        agentPubkey: agent.pk,
        allowedMerchants: [merchantObj],
    });

    const openPayment = mandate.buildOpenPaymentMandate({
        userPubkey: user.pk,
        userSk: user.sk,
        agentPubkey: agent.pk,
        currency: CURRENCY,
        maxAmount: LIMIT,
        allowedPayees: [merchantObj],
        openCheckout,
    });

    // Phase 1b: the merchant signs its checkout as a JWS; the hash is over that JWS.
    const amount = 12000;
    const checkoutPayload = {
        checkout_id: 'chk_1',
        merchant_id: merchantObj.id,
        total: { amount, currency: CURRENCY },
        iat: mandate.nowSec(),
        exp: mandate.nowSec() + 600,
    };
    const checkoutJwt = sdjwt.signJws(checkoutPayload, merchantKp.sk);
    const merchantCheckoutHash = checkoutHashOf(checkoutJwt);

    // Phase 2: the agent commits to the checkout and issues both closed mandates.
    const closedCheckout = mandate.buildClosedCheckoutMandate({
        agentPubkey: agent.pk, agentSk: agent.sk, checkoutJwt, openCheckout,
    });

    const closedPayment = mandate.buildClosedPaymentMandate({
        agentPubkey: agent.pk,
        agentSk: agent.sk,
        checkoutJwt,
        payee: merchantObj,
        paymentAmount: { amount, currency: CURRENCY },
        paymentInstrument,
        openPayment,
    });

    const presentations = {
        openCheckout: openCheckout.present(),
        openPayment: openPayment.present(),
        closedCheckout: closedCheckout.present(),
        closedPayment: closedPayment.present(),
    };

    const token = {
        payment_reference: hashPresented(closedPayment),
        checkout_hash: closedCheckout.claims.checkout_hash,
    };

    // The agent holds both mandates (cnf) and attaches a kb-sd-jwt to a presentation.
    const kbFor = (presentation, aud) => ({
        kbJwt: sdjwt.buildKbJwt({ presentation, nonce: NONCE, aud, holderSk: agent.sk }),
        nonce: NONCE,
        aud,
    });

    return {
        user, agent, merchantKp, merchantObj, amount, paymentInstrument,
        openCheckout, openPayment, checkoutJwt, merchantCheckoutHash,
        closedCheckout, closedPayment, presentations, token, kbFor,
    };
}

// Re-issue the closed Payment Mandate with overrides (used by the tamper cases).
function rebuildClosedPayment(w, overrides = {}) {
    return mandate.buildClosedPaymentMandate({
        agentPubkey: w.agent.pk,
        agentSk: w.agent.sk,
        checkoutJwt: w.checkoutJwt,
        payee: w.merchantObj,
        paymentAmount: { amount: w.amount, currency: CURRENCY },
        paymentInstrument: w.paymentInstrument,
        openPayment: w.openPayment,
        ...overrides,
    });
}

const merchantArgs = (w, over = {}) => {
    const openCheckoutPresentation = over.openCheckoutPresentation ?? w.presentations.openCheckout;
    const closedCheckoutPresentation = over.closedCheckoutPresentation ?? w.presentations.closedCheckout;
    return {
        openCheckoutPresentation,
        closedCheckoutPresentation,
        checkoutJwt: w.checkoutJwt,
        merchantCheckoutHash: w.merchantCheckoutHash,
        userPubkey: w.user.pk,
        merchantId: w.merchantObj.id,
        kb: w.kbFor(closedCheckoutPresentation, AUD.merchant),
        ...over,
    };
};

const cpArgs = (w, over = {}) => {
    const openPaymentPresentation = over.openPaymentPresentation ?? w.presentations.openPayment;
    const closedPaymentPresentation = over.closedPaymentPresentation ?? w.presentations.closedPayment;
    return {
        openPaymentPresentation,
        closedPaymentPresentation,
        openCheckoutPresentation: over.openCheckoutPresentation ?? w.presentations.openCheckout,
        userPubkey: w.user.pk,
        kb: w.kbFor(closedPaymentPresentation, AUD.cp),
        ...over,
    };
};

const mppArgs = (w, over = {}) => {
    const closedPaymentPresentation = over.closedPaymentPresentation ?? w.presentations.closedPayment;
    return {
        token: w.token,
        closedPaymentPresentation,
        closedCheckoutPresentation: over.closedCheckoutPresentation ?? w.presentations.closedCheckout,
        openCheckoutPresentation: over.openCheckoutPresentation ?? w.presentations.openCheckout,
        userPubkey: w.user.pk,
        kb: w.kbFor(closedPaymentPresentation, AUD.mpp),
        ...over,
    };
};

const allTrue = (res) => Object.keys(res).filter((k) => res[k] !== true);

// ---- happy path ----

test('四段 mandate 的 vct 与规范一致', () => {
    const w = makeWorld();
    assert.strictEqual(w.openCheckout.vct, 'mandate.checkout.open.1');
    assert.strictEqual(w.openPayment.vct, 'mandate.payment.open.1');
    assert.strictEqual(w.closedCheckout.vct, 'mandate.checkout.1');
    assert.strictEqual(w.closedPayment.vct, 'mandate.payment.1');

    // The wire form is a presentation string, and the disclosable claims are
    // committed as digests rather than carried in the signed payload.
    assert.match(w.presentations.openCheckout, /^[^~]+~[^~]+$/);
    const decoded = sdjwt.decodeJws(w.openCheckout.sdjwt);
    assert.strictEqual('constraints' in decoded.payload, false);
    assert.strictEqual(w.openCheckout.disclosures.length, 1);
    assert.strictEqual(w.openCheckout.claims.constraints.length, 1);
});

test('Merchant 验证 closed Checkout + 评估 open Checkout 约束：通过', () => {
    const w = makeWorld();
    const res = verify.verifyCheckoutMandates(merchantArgs(w));
    assert.deepStrictEqual(allTrue(res), [], JSON.stringify(res, null, 2));
});

test('CP 验证 closed Payment + 评估 open Payment 约束：通过', () => {
    const w = makeWorld();
    const res = verify.verifyPaymentMandates(cpArgs(w));
    assert.deepStrictEqual(allTrue(res), [], JSON.stringify(res, null, 2));
});

test('MPP 验证 credential 绑定到 checkout：通过', () => {
    const w = makeWorld();
    const res = verify.verifyAtMpp(mppArgs(w));
    assert.deepStrictEqual(allTrue(res), [], JSON.stringify(res, null, 2));
});

test('两条绑定链同值：transaction_id == checkout_hash', () => {
    const w = makeWorld();
    assert.strictEqual(w.closedPayment.claims.transaction_id, w.closedCheckout.claims.checkout_hash);
});

test('payment.reference 绑定 open Checkout', () => {
    const w = makeWorld();
    const ref = w.openPayment.claims.constraints.find((c) => c.type === 'payment.reference');
    assert.strictEqual(ref.conditional_transaction_id, hashPresented(w.presentations.openCheckout));
});

// ---- tamper: each role must reject ----

test('超上限：CP 拒绝（amount_range）', () => {
    const w = makeWorld();
    const closedPayment = rebuildClosedPayment(w, {
        paymentAmount: { amount: LIMIT + 1, currency: CURRENCY },
    });
    const res = verify.verifyPaymentMandates(cpArgs(w, {
        closedPaymentPresentation: closedPayment.present(),
    }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['constraint:payment.amount_range'], false);
});

test('改收款方：CP 拒绝（allowed_payees）', () => {
    const w = makeWorld();
    const closedPayment = rebuildClosedPayment(w, {
        payee: { id: 7, name: 'Evil', website: 'https://evil.example' },
    });
    const res = verify.verifyPaymentMandates(cpArgs(w, {
        closedPaymentPresentation: closedPayment.present(),
    }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['constraint:payment.allowed_payees'], false);
});

test('篡改 checkout：Merchant 拒绝（checkout_hash）', () => {
    const w = makeWorld();
    const res = verify.verifyCheckoutMandates(merchantArgs(w, { merchantCheckoutHash: 'deadbeef' }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['closedCheckout.checkout_hash.matchesMerchant'], false);
});

test('非授权商家：Merchant 拒绝（allowed_merchants）', () => {
    const w = makeWorld();
    const res = verify.verifyCheckoutMandates(merchantArgs(w, { merchantId: 9 }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['constraint:checkout.allowed_merchants'], false);
});

test('冒充 agent 签名：Merchant 拒绝（cnf 背书的 key 不匹配）', () => {
    const w = makeWorld();
    const impostor = keys.generateKeypair();
    // The impostor issues a closed mandate under its own key; the open mandate
    // still endorses the real agent, so the verifier checks against that key.
    const closedCheckout = mandate.buildClosedCheckoutMandate({
        agentPubkey: impostor.pk,
        agentSk: impostor.sk,
        checkoutJwt: w.checkoutJwt,
        openCheckout: w.openCheckout,
    });
    const res = verify.verifyCheckoutMandates(merchantArgs(w, {
        closedCheckoutPresentation: closedCheckout.present(),
    }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['closedCheckout.iss'], false);
});

test('换用户信任锚：全部拒绝', () => {
    const w = makeWorld();
    const other = keys.generateKeypair();
    const m = verify.verifyCheckoutMandates(merchantArgs(w, { userPubkey: other.pk }));
    const c = verify.verifyPaymentMandates(cpArgs(w, { userPubkey: other.pk }));
    assert.strictEqual(m.ok, false);
    assert.strictEqual(c.ok, false);
});

test('未知约束类型：按规范判为失败', () => {
    const w = makeWorld();
    const res = verify.evaluateConstraint({ type: 'payment.unknown_thing' }, w.closedPayment.claims, {});
    assert.strictEqual(res.pass, false);
});

test('sd_hash 不匹配：CP 拒绝', () => {
    const w = makeWorld();
    // The closed mandate is issued against a different open Payment Mandate, so
    // its sd_hash does not bind the one the CP is shown.
    const decoyOpenPayment = mandate.buildOpenPaymentMandate({
        userPubkey: w.user.pk,
        userSk: w.user.sk,
        agentPubkey: w.agent.pk,
        currency: CURRENCY,
        maxAmount: LIMIT - 1,
        allowedPayees: [w.merchantObj],
        openCheckout: w.openCheckout,
    });
    const closedPayment = rebuildClosedPayment(w, { openPayment: decoyOpenPayment });
    const res = verify.verifyPaymentMandates(cpArgs(w, {
        closedPaymentPresentation: closedPayment.present(),
    }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['closedPayment.sd_hash'], false);
});

// ---- selective disclosure: a withheld disclosure must not be silently accepted ----

test('省略 constraints 披露：CP 拒绝（必需 claim 缺失，不能绕过消费上限）', () => {
    const w = makeWorld();
    // An agent presenting the open Payment Mandate without its constraints
    // disclosure would otherwise leave nothing to evaluate.
    const res = verify.verifyPaymentMandates(cpArgs(w, {
        openPaymentPresentation: w.openPayment.present([]),
    }));
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res['openPayment.signature'], false);
    assert.ok(!('constraint:payment.amount_range' in res), 'constraints must not be evaluated when withheld');
});

// ---- receipts ----

test('Checkout Receipt 字段符合规范（成功/失败两种）', () => {
    const merchantKp = keys.generateKeypair();
    const ok = mandate.buildCheckoutReceipt({
        iss: merchantKp.pk, sk: merchantKp.sk, status: 'Success', reference: 'abc',
    });
    const verified = sdjwt.verifyJws(ok.sdjwt, merchantKp.pk);
    assert.strictEqual(verified.ok, true);
    assert.strictEqual(ok.claims.status, 'Success');
    assert.strictEqual(ok.claims.iss, merchantKp.pk);
    assert.strictEqual(typeof ok.claims.iat, 'number');
    assert.strictEqual(ok.claims.reference, 'abc');
    assert.ok(typeof ok.claims.order_id === 'string' && ok.claims.order_id.length > 0);
    assert.ok(!('error' in ok.claims));

    const err = mandate.buildCheckoutReceipt({
        iss: merchantKp.pk, sk: merchantKp.sk, status: 'Error', reference: 'abc', error: 'invalid_mandate',
    });
    assert.strictEqual(err.claims.error, 'invalid_mandate');
    assert.ok(!('order_id' in err.claims));
});

test('Payment Receipt 字段符合规范（成功/失败两种）', () => {
    const mppKp = keys.generateKeypair();
    const ok = mandate.buildPaymentReceipt({
        iss: mppKp.pk, sk: mppKp.sk, status: 'Success', reference: 'abc', paymentId: 'pay_1',
    });
    const verified = sdjwt.verifyJws(ok.sdjwt, mppKp.pk);
    assert.strictEqual(verified.ok, true);
    assert.strictEqual(ok.claims.status, 'Success');
    assert.strictEqual(ok.claims.payment_id, 'pay_1');
    assert.ok(typeof ok.claims.psp_confirmation_id === 'string');
    assert.ok(!('error' in ok.claims));

    const err = mandate.buildPaymentReceipt({
        iss: mppKp.pk, sk: mppKp.sk, status: 'Error', reference: 'abc', paymentId: 'pay_1', error: 'invalid_mandate',
    });
    assert.strictEqual(err.claims.error, 'invalid_mandate');
    assert.ok(!('psp_confirmation_id' in err.claims));
});
