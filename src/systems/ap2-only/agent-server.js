// AP2 Shopping Agent — Human Not Present flow, SD-JWT transport.
//
// Sequence (https://ap2-protocol.org/ap2/flows/#human-not-present):
//   1a  the User signs the open Checkout and open Payment Mandates
//   1b  the Agent collects merchant-signed checkouts
//   2   the Agent signs the closed Checkout and closed Payment Mandates, the
//       Merchant verifies the checkout half, the Credential Provider verifies the
//       payment half and issues a token, and the MPP settles and issues a receipt.
//
// Encoding (docs/sdjwt-contract.md §3): the User issues the open mandates and the
// Agent issues the closed ones as SD-JWTs (src/mandates/sdjwt.js). Only presentation
// strings cross the wire — the mandate handles stay inside the process. The Verifier
// is the nonce issuer: before forwarding a presentation the Agent fetches a single-use
// nonce (GET /nonce) and attaches a kb-sd-jwt over that exact presentation, signed by
// the agent key the open mandate endorses in `cnf`.
//
// The agent may deviate in the three ways the paper studies (discriminatory bidding,
// comparison manipulation, suboptimal selection); each deviation is applied to the
// same flow, so whatever the verifiers accept is what AP2 accepts.

const http = require('http');
const path = require('path');
const keys = require('../../mandates/keys');
const mandate = require('../../mandates/mandate');
const sdjwt = require('../../mandates/sdjwt');
const { jwkToPub } = require('../../mandates/jwk');
const { sendJSON, readJSON, cors, serveStatic } = require('../common/http-utils');

const WEB_ROOT = path.join(__dirname, '..', '..', 'web');
const CURRENCY = 'USD';

// Claims a verifier needs before it can evaluate an open mandate: in particular the
// `constraints` disclosure, without which there is no cap/allowlist to check.
const OPEN_REQUIRED = ['vct', 'iss', 'constraints', 'cnf', 'iat', 'exp'];

// Audience strings for the kb-sd-jwt `aud` claim. The nonce is requested from the
// verifier with the same audience so the binding is checked end to end.
const AUD = {
    merchant: 'merchant',
    cp: 'credential-provider',
    mpp: 'merchant-payment-processor',
};

// Compressed public key hex for a private key (used to validate the caller's key pair).
function publicKeyOf(skHex) {
    return keys.fromPrivate(skHex).getPublic(true, 'hex');
}

// The agent key endorsed by an open mandate's `cnf` claim, or null when unusable.
function endorsedAgentKey(claims) {
    try {
        return jwkToPub(claims && claims.cnf && claims.cnf.jwk);
    } catch (e) {
        return null;
    }
}

// Verify one open mandate presentation under the user trust anchor and check the
// claims the downstream roles depend on.
function verifyOpenPresentation({ label, presentation, issuerPubkey, vct }) {
    if (typeof presentation !== 'string' || presentation.length === 0) {
        return { ok: false, reason: label + ' presentation is required' };
    }
    const verified = sdjwt.verifyPresentation({
        presentation,
        issuerPubkey,
        requiredClaims: OPEN_REQUIRED,
    });
    if (!verified.ok) return { ok: false, reason: label + ': ' + verified.reason };

    const claims = verified.claims;
    if (claims.vct !== vct) return { ok: false, reason: label + ': vct must be ' + vct };
    if (claims.iss !== issuerPubkey) return { ok: false, reason: label + ': issuer is not the enrolled user' };
    if (mandate.isExpired(claims)) return { ok: false, reason: label + ': mandate expired or missing exp' };
    return { ok: true, claims };
}

function createHandler({ merchantUrl, providerUrl, mppUrl, verifierUrl }) {
    let session = null;

    function ensureSession() {
        if (!session) {
            session = {
                agentKp: keys.generateKeypair(),
                userPubkey: null,
                openCheckout: null,
                openPayment: null,
                result: null,
            };
        }
        return session;
    }

    const now = () => performance.now();

    // GET /nonce on the verifier: single use, short TTL. The verifier returns the
    // audience it recorded, which is the value the kb-jwt has to carry.
    async function fetchNonce(audience) {
        if (!verifierUrl) throw new Error('no verifier URL configured');
        const resp = await fetch(`${verifierUrl}/nonce?aud=${encodeURIComponent(audience)}`);
        if (!resp.ok) throw new Error(`verifier /nonce returned ${resp.status}`);
        const data = await resp.json();
        if (!data || typeof data.nonce !== 'string' || data.nonce.length === 0) {
            throw new Error('verifier /nonce returned no nonce');
        }
        const aud = typeof data.aud === 'string' && data.aud.length > 0 ? data.aud : audience;
        return { nonce: data.nonce, aud };
    }

    // Build the kb object the downstream roles expect: { kbJwt, nonce, aud } over the
    // presentation that is being forwarded. A missing verifier is downgraded to a
    // warning so the AP2-only stack (which can run without a verifier process) still
    // completes; with a verifier running every forward carries a binding.
    async function attachKeyBinding(presentation, audience, warnings) {
        try {
            const { nonce, aud } = await fetchNonce(audience);
            const holderSk = ensureSession().agentKp.sk;
            return {
                kbJwt: sdjwt.buildKbJwt({ presentation, nonce, aud, holderSk }),
                nonce,
                aud,
            };
        } catch (e) {
            warnings.push(`Key binding for ${audience} unavailable: ${e.message}`);
            return undefined;
        }
    }

    async function fetchCheckout(id, bid) {
        const q = bid === undefined ? '' : `?bid=${bid}`;
        try {
            const resp = await fetch(`${merchantUrl}/quote/${id}${q}`);
            const data = await resp.json();
            if (!resp.ok) return null;
            return data;
        } catch (e) {
            return null;
        }
    }

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        const url = new URL(req.url, 'http://localhost');
        const pathname = url.pathname;

        // ---- GET /pubkey ----
        if (req.method === 'GET' && pathname === '/pubkey') {
            const s = ensureSession();
            return sendJSON(res, 200, { signingPubkey: s.agentKp.pk });
        }

        // ---- POST /build-mandate — draft and sign the open mandates for the user ----
        // Body: { userPubkey, userSk, currency?, maxAmount, allowedMerchants? }
        // The caller supplies both halves of the user key: the secret key is required
        // because the open mandates are SD-JWTs signed at build time, and the public
        // key has to match it (it is the trust anchor every later role verifies with).
        if (req.method === 'POST' && pathname === '/build-mandate') {
            try {
                const body = await readJSON(req);
                const { userPubkey, userSk, currency, maxAmount, allowedMerchants } = body || {};
                if (typeof userPubkey !== 'string' || userPubkey.length === 0
                    || typeof userSk !== 'string' || userSk.length === 0) {
                    return sendJSON(res, 400, { error: 'Missing userPubkey or userSk' });
                }
                if (typeof maxAmount !== 'number') {
                    return sendJSON(res, 400, { error: 'Missing maxAmount' });
                }
                let derived;
                try {
                    derived = publicKeyOf(userSk);
                } catch (e) {
                    return sendJSON(res, 400, { error: 'Invalid userSk: ' + e.message });
                }
                if (derived !== userPubkey) {
                    return sendJSON(res, 400, { error: 'userSk does not match userPubkey' });
                }

                const s = ensureSession();
                s.userPubkey = userPubkey;

                const allowed = (Array.isArray(allowedMerchants) && allowedMerchants.length > 0)
                    ? allowedMerchants
                    : [mandate.merchant({ id: 0, name: 'Merchant 0', website: 'https://merchant0.example' })];

                const openCheckout = mandate.buildOpenCheckoutMandate({
                    userPubkey,
                    userSk,
                    agentPubkey: s.agentKp.pk,
                    allowedMerchants: allowed,
                });
                const openPayment = mandate.buildOpenPaymentMandate({
                    userPubkey,
                    userSk,
                    agentPubkey: s.agentKp.pk,
                    currency: currency || CURRENCY,
                    maxAmount,
                    allowedPayees: allowed,
                    openCheckout,
                });
                s.openCheckout = openCheckout;
                s.openPayment = openPayment;

                // Only the presentation strings are handed to the caller; they are what
                // /execute forwards onward. The claims are returned for inspection only.
                const openCheckoutPresentation = openCheckout.present();
                const openPaymentPresentation = openPayment.present();
                s.openCheckoutPresentation = openCheckoutPresentation;
                s.openPaymentPresentation = openPaymentPresentation;

                return sendJSON(res, 200, {
                    openCheckoutPresentation,
                    openPaymentPresentation,
                    // Legacy aliases: the wire artefact under the historical field name.
                    openCheckout: openCheckoutPresentation,
                    openPayment: openPaymentPresentation,
                    openCheckoutClaims: openCheckout.claims,
                    openPaymentClaims: openPayment.claims,
                });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- POST /execute — the agent completes the purchase autonomously ----
        // Body: { openCheckoutPresentation, openPaymentPresentation, userPubkey?,
        //         cheat?, target?, verifyMerchantSignatures? }
        if (req.method === 'POST' && pathname === '/execute') {
            const tTotal = now();
            const warnings = [];
            try {
                const body = (await readJSON(req)) || {};
                const s = ensureSession();
                const anchor = body.userPubkey || s.userPubkey;
                if (!anchor) {
                    return sendJSON(res, 400, { error: 'Unknown user: call /build-mandate first or send userPubkey' });
                }
                if (s.userPubkey && anchor !== s.userPubkey) {
                    return sendJSON(res, 400, { error: 'userPubkey is not the owner of this session' });
                }

                // Accept either the explicit presentation field or the legacy alias; the
                // value must be a presentation string, never a mandate object.
                const openCheckoutPresentation = typeof body.openCheckoutPresentation === 'string'
                    ? body.openCheckoutPresentation
                    : (typeof body.openCheckout === 'string' ? body.openCheckout : null);
                const openPaymentPresentation = typeof body.openPaymentPresentation === 'string'
                    ? body.openPaymentPresentation
                    : (typeof body.openPayment === 'string' ? body.openPayment : null);

                const openCheckout = verifyOpenPresentation({
                    label: 'open Checkout Mandate',
                    presentation: openCheckoutPresentation,
                    issuerPubkey: anchor,
                    vct: mandate.VCT.OPEN_CHECKOUT,
                });
                if (!openCheckout.ok) return sendJSON(res, 400, { error: openCheckout.reason });
                const openPayment = verifyOpenPresentation({
                    label: 'open Payment Mandate',
                    presentation: openPaymentPresentation,
                    issuerPubkey: anchor,
                    vct: mandate.VCT.OPEN_PAYMENT,
                });
                if (!openPayment.ok) return sendJSON(res, 400, { error: openPayment.reason });

                // The open mandates sender-constrain the closed ones to this agent key.
                const checkoutAgentKey = endorsedAgentKey(openCheckout.claims);
                const paymentAgentKey = endorsedAgentKey(openPayment.claims);
                if (checkoutAgentKey !== s.agentKp.pk) {
                    return sendJSON(res, 400, { error: 'Open Checkout Mandate does not endorse this agent key' });
                }
                if (paymentAgentKey !== s.agentKp.pk) {
                    return sendJSON(res, 400, { error: 'Open Payment Mandate does not endorse this agent key' });
                }

                const range = (openPayment.claims.constraints || []).find((c) => c.type === 'payment.amount_range');
                if (!range) return sendJSON(res, 400, { error: 'Open Payment Mandate has no amount_range constraint' });
                const limit = range.max;
                const currency = range.currency;

                const cheat = typeof body.cheat === 'string' ? body.cheat : 'none';

                // ---- 1b: collect merchant-signed checkouts ----
                const tHealth0 = now();
                const health = await (await fetch(`${merchantUrl}/health`)).json();
                const tHealth = now() - tHealth0;
                const count = health.quotes ? health.quotes.length : 4;
                const merchantKeysById = {};
                (health.merchants || []).forEach((m, i) => {
                    merchantKeysById[m.id] = health.merchantPubkeys[i];
                });

                const tQuotes0 = now();
                const firstRound = await Promise.all(
                    Array.from({ length: count }, (_, i) => fetchCheckout(i)),
                );
                const tQuotes = now() - tQuotes0;
                let responses = firstRound.filter(Boolean);

                // Merchant-side checkout signing is a per-merchant cost, and merchants are
                // independent parallel parties: report max (wall clock) and sum (the
                // single-process serialisation artifact the benchmark subtracts).
                const tCheckoutSignSum = responses.reduce((sum, r) => sum + (r.tCheckoutSignMs || 0), 0);
                const tCheckoutSignMax = responses.length
                    ? Math.max(...responses.map((r) => r.tCheckoutSignMs || 0))
                    : 0;
                // Full per-merchant checkout generation (payload + JWS + hash), so the
                // benchmark can remove the whole serialisation artifact, not only ECDSA.
                const tCheckoutGenSum = responses.reduce((sum, r) => sum + (r.tCheckoutGenMs || 0), 0);
                const tCheckoutGenMax = responses.length
                    ? Math.max(...responses.map((r) => r.tCheckoutGenMs || 0))
                    : 0;

                // Verifying merchant signatures is not an AP2 duty — the Merchant verifies
                // the closed Checkout against its own checkout JWT — so this is an optional
                // defensive check, off by default and excluded from the reported cost.
                // Under SD-JWT the checkout is a JWS, verified against the merchant key.
                let tVerifyMerchants = 0;
                if (body.verifyMerchantSignatures === true) {
                    const tVerify0 = now();
                    const verified = [];
                    for (const r of responses) {
                        const mk = merchantKeysById[r.id];
                        if (!mk) { warnings.push(`Merchant ${r.id}: unknown key`); continue; }
                        if (!sdjwt.verifyJws(r.checkoutJwt, mk).ok) {
                            warnings.push(`Merchant ${r.id}: invalid checkout signature`);
                            continue;
                        }
                        verified.push(r);
                    }
                    responses = verified;
                    tVerifyMerchants = now() - tVerify0;
                }

                const feasible = responses
                    .filter((r) => r.quote < limit)
                    .sort((a, b) => a.quote - b.quote);
                const honest = feasible.length > 0 ? feasible[0] : null;
                const honestPrice = honest ? honest.quote : null;
                const honestMerchantId = honest ? honest.id : null;

                // ---- deviations (AP2-only studies: the flow authorises them) ----
                let candidates = feasible.slice();
                if (cheat === 'discriminatory-bid' && honest) {
                    // Re-enter bidding: bid below the cheapest merchant's ask so that it
                    // rejects, then use whatever is left.
                    const retry = await fetchCheckout(honest.id, Math.max(0, honest.quote - 1));
                    if (retry && retry.rejected) {
                        candidates = feasible.filter((r) => r.id !== honest.id);
                        warnings.push(`Deviation: merchant ${honest.id} rejected the bid`);
                    }
                } else if (cheat === 'omit-cheapest' && honest) {
                    candidates = feasible.filter((r) => r.id !== honest.id);
                    warnings.push(`Deviation: offer of merchant ${honest.id} omitted`);
                }

                if (candidates.length === 0) {
                    return sendJSON(res, 200, {
                        result: {
                            chosen: null, chosenMerchantId: null, chosenPrice: null,
                            honestMerchantId, honestPrice, cheat,
                            quotes: responses.map((r) => ({ id: r.id, quote: r.quote })),
                            limit, currency, warnings,
                            openCheckout: openCheckoutPresentation,
                            openPayment: openPaymentPresentation,
                            openCheckoutClaims: openCheckout.claims,
                            openPaymentClaims: openPayment.claims,
                            closedCheckout: null, closedPayment: null,
                            closedCheckoutClaims: null, closedPaymentClaims: null,
                            checkoutReceipt: null, paymentReceipt: null, token: null,
                            checks: { merchant: null, cp: null, mpp: null },
                            timingMs: { total: +(now() - tTotal).toFixed(1) },
                        },
                    });
                }

                let selected;
                if (cheat === 'inferior-selection') {
                    const target = typeof body.target === 'number' ? body.target : null;
                    const preferred = target === null ? null : candidates.find((r) => r.id === target);
                    selected = preferred || candidates[candidates.length - 1];
                } else {
                    selected = candidates[0];
                }

                // ---- 2: the agent commits to the checkout (SD-JWT handles, signed here) ----
                const tClosed0 = now();
                const closedCheckoutHandle = mandate.buildClosedCheckoutMandate({
                    agentPubkey: s.agentKp.pk,
                    agentSk: s.agentKp.sk,
                    checkoutJwt: selected.checkoutJwt,
                    openCheckout: openCheckoutPresentation,
                });
                const closedPaymentHandle = mandate.buildClosedPaymentMandate({
                    agentPubkey: s.agentKp.pk,
                    agentSk: s.agentKp.sk,
                    checkoutJwt: selected.checkoutJwt,
                    payee: selected.merchant,
                    paymentAmount: { amount: selected.quote, currency },
                    paymentInstrument: { id: 'pi_demo', type: 'card', description: 'demo instrument' },
                    openPayment: openPaymentPresentation,
                });
                const closedCheckoutPresentation = closedCheckoutHandle.present();
                const closedPaymentPresentation = closedPaymentHandle.present();
                const tBuildClosed = now() - tClosed0;

                // ---- merchant verifies the checkout half ----
                const tVerify0 = now();
                const tMerchant0 = now();
                const merchantKb = await attachKeyBinding(closedCheckoutPresentation, AUD.merchant, warnings);
                const merchantResp = await fetch(`${merchantUrl}/verify-checkout`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        openCheckoutPresentation,
                        closedCheckoutPresentation,
                        checkoutJwt: selected.checkoutJwt,
                        userPubkey: anchor,
                        ...(merchantKb ? { kb: merchantKb } : {}),
                    }),
                });
                const merchantData = await merchantResp.json();
                const tMerchantVerify = now() - tMerchant0;
                const checkoutReceipt = merchantData.receipt || null;
                const checkoutAccepted = merchantResp.ok && merchantData.checks && merchantData.checks.ok;

                // ---- CP verifies the payment half and issues a token ----
                let token = null;
                let paymentReceipt = null;
                let cpChecks = null;
                let mppChecks = null;
                let tCp = 0;
                let tMpp = 0;
                if (checkoutAccepted) {
                    const tCp0 = now();
                    const cpKb = await attachKeyBinding(closedPaymentPresentation, AUD.cp, warnings);
                    const cpResp = await fetch(`${providerUrl}/issue`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            openPaymentPresentation,
                            closedPaymentPresentation,
                            openCheckoutPresentation,
                            userPubkey: anchor,
                            ...(cpKb ? { kb: cpKb } : {}),
                        }),
                    });
                    const cpData = await cpResp.json();
                    tCp = now() - tCp0;
                    cpChecks = cpData.checks || null;
                    if (cpResp.ok) {
                        token = cpData.token;
                        // ---- MPP settles ----
                        const tMpp0 = now();
                        const mppKb = await attachKeyBinding(closedPaymentPresentation, AUD.mpp, warnings);
                        const mppResp = await fetch(`${mppUrl}/process`, {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token,
                                tokenJwt: cpData.tokenJwt,
                                closedPaymentPresentation,
                                closedCheckoutPresentation,
                                openCheckoutPresentation,
                                userPubkey: anchor,
                                ...(mppKb ? { kb: mppKb } : {}),
                            }),
                        });
                        const mppData = await mppResp.json();
                        tMpp = now() - tMpp0;
                        mppChecks = mppData.checks || null;
                        paymentReceipt = mppData.receipt || null;
                    } else {
                        paymentReceipt = cpData.receipt || null;
                        warnings.push('Credential Provider rejected the Payment Mandate');
                    }
                } else {
                    warnings.push('Merchant rejected the Checkout Mandate');
                }
                const tVerify = now() - tVerify0;

                const result = {
                    chosen: selected.id,
                    chosenMerchantId: selected.id,
                    chosenPrice: selected.quote,
                    honestMerchantId,
                    honestPrice,
                    cheat,
                    limit,
                    currency,
                    quotes: responses.map((r) => ({ id: r.id, quote: r.quote })),
                    // Wire artefacts: presentations only, never the handles.
                    openCheckout: openCheckoutPresentation,
                    openPayment: openPaymentPresentation,
                    closedCheckout: closedCheckoutPresentation,
                    closedPayment: closedPaymentPresentation,
                    // Recovered/issued claims, for local inspection (never forwarded whole).
                    openCheckoutClaims: openCheckout.claims,
                    openPaymentClaims: openPayment.claims,
                    closedCheckoutClaims: closedCheckoutHandle.claims,
                    closedPaymentClaims: closedPaymentHandle.claims,
                    checkoutReceipt,
                    paymentReceipt,
                    token,
                    checks: {
                        merchant: merchantData.checks || null,
                        cp: cpChecks,
                        mpp: mppChecks,
                    },
                    timingMs: {
                        total: +(now() - tTotal).toFixed(1),
                        health: +tHealth.toFixed(1),
                        quotes: +tQuotes.toFixed(1),
                        checkoutSignMax: +tCheckoutSignMax.toFixed(2),
                        checkoutSignSum: +tCheckoutSignSum.toFixed(2),
                        checkoutGenMax: +tCheckoutGenMax.toFixed(2),
                        checkoutGenSum: +tCheckoutGenSum.toFixed(2),
                        verifyMerchants: +tVerifyMerchants.toFixed(1),
                        buildClosed: +tBuildClosed.toFixed(1),
                        merchantVerify: +tMerchantVerify.toFixed(1),
                        cp: +tCp.toFixed(1),
                        mpp: +tMpp.toFixed(1),
                        verify: +tVerify.toFixed(1),
                    },
                    warnings,
                };
                s.result = result;
                return sendJSON(res, 200, { result });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message, warnings });
            }
        }

        if (req.method === 'GET' && pathname === '/result') {
            if (!session || !session.result) return sendJSON(res, 404, { error: 'No result. Run /build-mandate then /execute.' });
            return sendJSON(res, 200, { result: session.result });
        }

        if (req.method === 'POST' && pathname === '/reset') {
            session = null;
            return sendJSON(res, 200, { ok: true });
        }

        if (req.method === 'GET' && pathname === '/health') {
            return sendJSON(res, 200, { ok: true, verifierUrl });
        }

        if (req.method === 'GET') return serveStatic(WEB_ROOT, decodeURIComponent(pathname), res);

        sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3201;
    const merchantUrl = opts.merchantUrl || 'http://localhost:3210';
    const providerUrl = opts.providerUrl || 'http://localhost:3290';
    const mppUrl = opts.mppUrl || 'http://localhost:3390';
    // The verifier is only the nonce issuer for this agent; the AP2 role checks run at
    // the Merchant, the Credential Provider and the MPP.
    const verifierUrl = opts.verifierUrl || 'http://localhost:3190';
    const handler = createHandler({ merchantUrl, providerUrl, mppUrl, verifierUrl });
    const server = http.createServer(handler);
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`✓ AP2 Agent Server: http://localhost:${port}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('../common/http-utils');
    start({
        port: parseInt(getArg(process.argv, '--port', '3201'), 10),
        merchantUrl: getArg(process.argv, '--merchant-url', 'http://localhost:3210'),
        providerUrl: getArg(process.argv, '--provider-url', 'http://localhost:3290'),
        mppUrl: getArg(process.argv, '--mpp-url', 'http://localhost:3390'),
        verifierUrl: getArg(process.argv, '--verifier-url', 'http://localhost:3190'),
    });
}

module.exports = { start };
