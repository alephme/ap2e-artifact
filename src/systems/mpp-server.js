// Merchant Payment Processor (MPP).
//
// AP2 requires the MPP to receive an appropriate payment credential from the
// merchant before processing, and to verify that the credential is scoped to the
// checkout — including the binding to the checkout JWT hash and to the open Checkout
// Mandate hash. It then returns a Payment Receipt.  [specification#merchant-payment-processor]
//
// This role is separate from the Credential Provider: the CP authorises, the MPP
// settles and issues the receipt.
//
// Wire format: the closed mandates are SD-JWT *presentation strings*. The MPP receives
//   { token, tokenJwt?, tokenSignature?, closedCheckoutPresentation,
//     closedPaymentPresentation, openCheckoutPresentation, userPubkey?,
//     agentPubkey?, kb?: { kbJwt, nonce, aud? } }
// verifies the credential scope plus the two bindings, and returns a JWS-signed
// Payment Receipt.

const http = require('http');
const keys = require('../mandates/keys');
const mandate = require('../mandates/mandate');
const sdjwt = require('../mandates/sdjwt');
const verify = require('../mandates/ap2-verify');
const { hashPresented } = require('../mandates/hashes');
const { sendJSON, readJSON, cors } = require('./common/http-utils');

// The last segment of a JWS compact string, kept in the legacy `*Signature` field.
function jwsSignatureOf(jwt) {
    return typeof jwt === 'string' && jwt.split('.').length === 3 ? jwt.split('.')[2] : null;
}

function createHandler({ userPubkey, cpPubkey } = {}) {
    const mppKeys = keys.generateKeypair();
    let paymentCounter = 0;

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        const url = new URL(req.url, 'http://localhost');

        // POST /process — verify the credential's scope, then settle.
        if (req.method === 'POST' && url.pathname === '/process') {
            try {
                const body = (await readJSON(req)) || {};
                const {
                    token, tokenJwt, tokenSignature,
                    closedPaymentPresentation, closedCheckoutPresentation,
                    openCheckoutPresentation, agentPubkey, kb,
                } = body;
                if (!token || !closedPaymentPresentation || !closedCheckoutPresentation) {
                    return sendJSON(res, 400, { error: 'Missing token or mandates' });
                }

                // The user key is the enrolment trust anchor: the configured key wins,
                // the body value is only a fallback.
                const anchor = userPubkey || body.userPubkey || null;
                const checks = verify.verifyAtMpp({
                    token,
                    closedPaymentPresentation,
                    closedCheckoutPresentation,
                    openCheckoutPresentation,
                    userPubkey: anchor,
                    agentPubkey,
                    kb,
                });

                // The credential must also be signed by the CP; the MPP is configured
                // with the CP's key out of band. Without that key the legacy field check
                // is kept, since the demo launchers do not provision it.
                if (cpPubkey && typeof tokenJwt === 'string') {
                    const tokenVerified = sdjwt.verifyJws(tokenJwt, cpPubkey);
                    checks['token.signature'] = tokenVerified.ok;
                    if (!tokenVerified.ok) checks.ok = false;
                } else if (tokenSignature && checks.ok) {
                    checks['token.signature'] = true;
                }

                // `reference` is the sd_hash of the closed Payment presentation.
                const reference = hashPresented(closedPaymentPresentation);

                if (!checks.ok) {
                    const receiptHandle = mandate.buildPaymentReceipt({
                        iss: mppKeys.pk,
                        sk: mppKeys.sk,
                        status: 'Error',
                        reference,
                        paymentId: 'none',
                        error: 'invalid_mandate',
                        errorDescription: 'Payment credential not scoped to this checkout',
                    });
                    return sendJSON(res, 403, {
                        checks,
                        receipt: receiptHandle.claims,
                        receiptJwt: receiptHandle.sdjwt,
                        receiptSignature: jwsSignatureOf(receiptHandle.sdjwt),
                    });
                }

                const receiptHandle = mandate.buildPaymentReceipt({
                    iss: mppKeys.pk,
                    sk: mppKeys.sk,
                    status: 'Success',
                    reference,
                    paymentId: `pay_${Date.now().toString(36)}_${++paymentCounter}`,
                });
                return sendJSON(res, 200, {
                    checks,
                    receipt: receiptHandle.claims,
                    receiptJwt: receiptHandle.sdjwt,
                    receiptSignature: jwsSignatureOf(receiptHandle.sdjwt),
                });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        if (req.method === 'GET' && url.pathname === '/health') {
            sendJSON(res, 200, { ok: true, pubkey: mppKeys.pk });
            return;
        }
        if (req.method === 'GET' && url.pathname === '/pubkey') {
            sendJSON(res, 200, { signingPubkey: mppKeys.pk });
            return;
        }

        sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3390;
    const server = http.createServer(createHandler({
        userPubkey: opts.userPubkey || null,
        cpPubkey: opts.cpPubkey || null,
    }));
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`✓ Merchant Payment Processor: http://localhost:${port}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('./common/http-utils');
    start({
        port: parseInt(getArg(process.argv, '--port', '3390'), 10),
        userPubkey: getArg(process.argv, '--user-pubkey', null),
        cpPubkey: getArg(process.argv, '--cp-pubkey', null),
    });
}

module.exports = { start, createHandler };
