// Credential Provider — verifies the Payment Mandates and issues a payment token.
//
// AP2 requires the CP (and, if applicable, the Network) to receive an appropriate
// Payment Mandate before returning a payment credential, to verify it, and to
// evaluate every constraint of the open Payment Mandate. On failure it must return
// a Payment Receipt carrying the error.  [specification#credential-provider-and-network]
//
// The CP is the only party that sees the payment side, so it never verifies the
// merchant's checkout; it relies on the merchant for that and on `transaction_id`
// for the binding.
//
// Wire format: every mandate is an SD-JWT *presentation string*. The CP receives
//   { openPaymentPresentation, closedPaymentPresentation, openCheckoutPresentation?,
//     userPubkey?, zkpVerified?, kb?: { kbJwt, nonce, aud? } }
// verifies the two payment presentations with the explicit user trust anchor, and
// recovers the closed mandate claims it needs for the credential by verifying the
// presentations itself (ap2-verify only reports the check verdicts).

const http = require('http');
const keys = require('../mandates/keys');
const mandate = require('../mandates/mandate');
const sdjwt = require('../mandates/sdjwt');
const verify = require('../mandates/ap2-verify');
const { hashPresented } = require('../mandates/hashes');
const { jwkToPub } = require('../mandates/jwk');
const { sendJSON, readJSON, cors } = require('./common/http-utils');

// Recover the closed Payment Mandate claims from the presentations. The agent key
// is the one endorsed by the open Payment Mandate `cnf` claim; it is never taken
// from the artefact being verified.
function recoverClosedPaymentClaims({ openPaymentPresentation, closedPaymentPresentation, userPubkey }) {
    const open = sdjwt.verifyPresentation({
        presentation: openPaymentPresentation,
        issuerPubkey: userPubkey,
        requiredClaims: ['cnf'],
    });
    if (!open.ok) return null;
    let agentKey;
    try {
        agentKey = jwkToPub(open.claims.cnf.jwk);
    } catch (e) {
        return null;
    }
    const closed = sdjwt.verifyPresentation({
        presentation: closedPaymentPresentation,
        issuerPubkey: agentKey,
    });
    return closed.ok ? closed.claims : null;
}

// The last segment of a JWS compact string, kept in the legacy `*Signature` field.
function jwsSignatureOf(jwt) {
    return typeof jwt === 'string' && jwt.split('.').length === 3 ? jwt.split('.')[2] : null;
}

function createHandler({ userPubkey }) {
    const cpKeys = keys.generateKeypair();
    let tokenCounter = 0;

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        const url = new URL(req.url, 'http://localhost');

        // POST /issue — verify the Payment Mandate presentations, then issue a scoped
        // token (success) or a JWS-signed Payment Receipt (failure).
        if (req.method === 'POST' && url.pathname === '/issue') {
            try {
                const body = (await readJSON(req)) || {};
                const {
                    openPaymentPresentation, closedPaymentPresentation,
                    openCheckoutPresentation, zkpVerified, kb,
                } = body;

                if (!openPaymentPresentation || !closedPaymentPresentation) {
                    return sendJSON(res, 400, { error: 'Missing Payment Mandates' });
                }
                // The user key is the enrolment trust anchor: the configured key wins,
                // the body value is only a fallback.
                const anchor = userPubkey || body.userPubkey || null;

                const checks = verify.verifyPaymentMandates({
                    openPaymentPresentation,
                    closedPaymentPresentation,
                    openCheckoutPresentation,
                    userPubkey: anchor,
                    zkpVerified: zkpVerified === true,
                    kb,
                });

                // `reference` is the sd_hash of the closed Payment presentation.
                const reference = hashPresented(closedPaymentPresentation);

                if (!checks.ok) {
                    // AP2: return a Payment Receipt carrying the error.
                    const receiptHandle = mandate.buildPaymentReceipt({
                        iss: cpKeys.pk,
                        sk: cpKeys.sk,
                        status: 'Error',
                        reference,
                        paymentId: 'none',
                        error: 'invalid_mandate',
                        errorDescription: 'Payment Mandate verification failed',
                    });
                    return sendJSON(res, 403, {
                        checks,
                        receipt: receiptHandle.claims,
                        receiptJwt: receiptHandle.sdjwt,
                        receiptSignature: jwsSignatureOf(receiptHandle.sdjwt),
                    });
                }

                const closedClaims = recoverClosedPaymentClaims({
                    openPaymentPresentation,
                    closedPaymentPresentation,
                    userPubkey: anchor,
                });
                if (!closedClaims) {
                    return sendJSON(res, 400, { error: 'Could not recover the closed Payment Mandate claims' });
                }

                // A scoped payment credential: bound to this payment mandate and to the
                // checkout it pays for. The token keeps its previous plain-object shape;
                // tokenJwt is the JWS-signed envelope and tokenSignature its last segment.
                const token = {
                    token_id: `tok_${Date.now().toString(36)}_${++tokenCounter}`,
                    payment_reference: reference,
                    checkout_hash: closedClaims.transaction_id,
                    amount: closedClaims.payment_amount,
                    payee: closedClaims.payee,
                    issued_at: mandate.nowSec(),
                };
                const tokenJwt = sdjwt.signJws(token, cpKeys.sk);
                const tokenSignature = jwsSignatureOf(tokenJwt);

                return sendJSON(res, 200, { checks, token, tokenJwt, tokenSignature });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        if (req.method === 'GET' && url.pathname === '/health') {
            sendJSON(res, 200, { ok: true, pubkey: cpKeys.pk });
            return;
        }
        if (req.method === 'GET' && url.pathname === '/pubkey') {
            sendJSON(res, 200, { signingPubkey: cpKeys.pk });
            return;
        }

        sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3290;
    const userPubkey = opts.userPubkey || null;
    const server = http.createServer(createHandler({ userPubkey }));
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`✓ Credential Provider: http://localhost:${port}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('./common/http-utils');
    start({
        port: parseInt(getArg(process.argv, '--port', '3290'), 10),
        userPubkey: getArg(process.argv, '--user-pubkey', null),
    });
}

module.exports = { start, createHandler };
