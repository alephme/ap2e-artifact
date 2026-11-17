// Merchant Server — one process hosting N merchant identities.
//
// Plain mode (AP2 baseline): GET /quote/{id} returns a merchant-signed checkout
// shaped as AP2 expects, together with its checkout_jwt and checkout_hash.
// POST /verify-checkout runs the merchant's half of AP2: verify the closed Checkout
// Mandate against the checkout this merchant signed, evaluate the open Checkout
// constraints, and return a Checkout Receipt.
//
// Sealed mode (the range-proof prototype): same, except the checkout carries a
// Pedersen commitment to the total instead of the plaintext amount, plus the
// price-validity proofs and the ECIES-sealed opening.
//
// Programmatic: start({ port, mode, quotes, userPubkey, providerUrl })
// CLI:          node src/systems/merchant-server.js --port PORT --mode plain|sealed --quotes 120,95
//
// When providerUrl is set and the request carries a qid, the merchant signs its
// response and submits it to the credential provider's /submit endpoint as well as
// returning it to the agent.

const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { hexToPoint: h2p } = require('../shopping/commitments');
const BN = require('bn.js');
const bn128 = require('../crypto/bn128');
const params = require('../crypto/params');
const ecies = require('../crypto/ecies');
const c = require('../crypto/c-backend');

const ZKP_MODE = process.env.ZKP_MODE || 'single';
const keys = require('../mandates/keys');
const mandate = require('../mandates/mandate');
const sdjwt = require('../mandates/sdjwt');
const verify = require('../mandates/ap2-verify');
const { checkoutHashOf } = require('../mandates/hashes');
const { sendJSON, readJSON, cors, serveStatic } = require('./common/http-utils');

const WEB_ROOT = path.join(__dirname, '..', 'web');
const CURRENCY = 'USD';

// The third segment of a JWS compact string. The checkout/receipt signature is
// carried inside the JWS itself; this helper keeps the legacy `*Signature` field
// names populated for callers that still read them.
function jwsSignatureOf(jwt) {
    return typeof jwt === 'string' && jwt.split('.').length === 3 ? jwt.split('.')[2] : null;
}

function merchantObject(id) {
    return { id, name: `Merchant ${id}`, website: `https://merchant${id}.example` };
}

// The checkout payload the merchant signs. This is what AP2 calls the checkout JWT.
function buildCheckoutPayload(merchantId, mode, quoteData) {
    const iat = mandate.nowSec();
    const base = {
        checkout_id: `m${merchantId}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
        merchant_id: merchantId,
        iat,
        exp: iat + 900,
    };
    if (mode === 'sealed') {
        return {
            ...base,
            items: [{ id: `item_${merchantId}`, title: `Offer ${merchantId}` }],
            total_commitment: quoteData.commitment,
        };
    }
    return {
        ...base,
        items: [{
            id: `item_${merchantId}`,
            title: `Offer ${merchantId}`,
            unit_price: { amount: quoteData.quote, currency: CURRENCY },
            quantity: 1,
        }],
        total: { amount: quoteData.quote, currency: CURRENCY },
    };
}

// Price-validity proofs（C 后端，single 模式，merchant 生成）。
function generatePriceProof(quoteInt, rBuf, n) {
    if (ZKP_MODE !== 'single') throw new Error('C backend: aggregated mode not yet wired');
    const tMin0 = performance.now();
    const piMin = c.prove(c.rangeCheck(quoteInt - 1, n), rBuf, n).proof;
    const tMin = performance.now() - tMin0;
    const tMax0 = performance.now();
    const negR = c.negBlind(rBuf, n);
    const piMax = c.prove(c.rangeCheck(Math.pow(2, n) - 1 - quoteInt, n), negR, n).proof;
    const tMax = performance.now() - tMax0;
    return {
        proof: { min: c.toHex(piMin), max: c.toHex(piMax) },
        timingMs: { min: +tMin.toFixed(1), max: +tMax.toFixed(1) },
    };
}

function createHandler({ mode, quotes: quotesIn, userPubkey, providerUrl, bidAttestation = false, responseStrategy = 'always-offer' }) {
    // Timeline reference: the first request this process ever handles.
    let merchantT0 = null;
    // Quote handlers are serialized: with many merchants in one process the async
    // awaits would otherwise interleave them, so a handler wall clock would include
    // time spent inside its siblings and mean nothing on its own.
    let quoteQueue = Promise.resolve();
    function withQuoteLock(fn) {
        const run = quoteQueue.then(fn, fn);
        quoteQueue = run.then(() => {}, () => {});
        return run;
    }
    // Mutable so a long-lived server can be handed a new quote set per scenario by the
    // benchmark harness (POST /quotes). In a deployment the operator sets prices itself.
    let quotes = quotesIn;
    let merchantKeys = quotes.map(() => keys.generateKeypair());
    // Checkouts this server has issued, keyed by checkout_jwt. AP2 requires the
    // merchant to compare against "the latest checkout_jwt" it produced.
    const issued = new Map();
    // Attested responses still travelling to the provider. Keeping them referenced
    // also keeps the event loop alive until the last submission settles.
    const pendingSubmits = new Set();

    // ---- bid attestation (AP2-E) ----
    // The merchant checks the bid it received against the commitment opening, then
    // signs a response containing that commitment. The signed response goes straight
    // to the provider, so the agent can neither alter nor suppress it.
    function checkBidOpening(bidParam, blindingHex, commitmentHex) {
        if (bidParam === null) return { ok: true, absent: true };
        const bid = parseInt(bidParam, 10);
        if (!Number.isFinite(bid)) return { ok: false, error: 'Invalid bid' };
        if (!blindingHex || !commitmentHex) return { ok: false, error: 'Missing bid opening' };
        try {
            const blind = new BN(blindingHex, 16).toRed(bn128.q);
            const expected = params.g.mul(new BN(bid).toRed(bn128.q)).add(params.h.mul(blind));
            const received = h2p(commitmentHex);
            if (!expected.eq(received)) {
                return { ok: false, error: 'Bid does not match its commitment opening' };
            }
            return { ok: true, bid };
        } catch (e) {
            return { ok: false, error: `Malformed bid opening: ${e.message}` };
        }
    }

    async function signAndSubmit({ qid, id, bidCommitment, kind, offer, n }) {
        if (!qid || !providerUrl) return null;
        const mk = merchantKeys[id];
        const iat = mandate.nowSec();
        const response = {
            qid, merchantId: id, bidCommitment,
            kind, offer: offer || null,
            n: n || null,
            iat, exp: iat + 300,
        };
        const signature = keys.sign(keys.hashJSON(response), mk.sk);
        // Submit in the background: the merchant answers the agent immediately and the
        // provider collects the attested response in parallel. The agent confirms
        // collection with /fix before it submits evidence, so nothing is lost by not
        // waiting here, and the agent's response time stays independent of how many
        // other merchants are submitting at the same moment.
        const t0 = performance.now();
        const submitPromise = fetch(`${providerUrl}/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ qid, response, signature }),
        }).catch(() => null);
        submitPromise.then(() => {
            pendingSubmits.delete(submitPromise);
        });
        pendingSubmits.add(submitPromise);
        return { response, responseSignature: signature, tSubmitMs: +(performance.now() - t0).toFixed(2) };
    }

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        if (merchantT0 === null) merchantT0 = performance.now();
        const tRecv = +(performance.now() - merchantT0).toFixed(1);

        const url = new URL(req.url, 'http://localhost');
        const pathname = url.pathname;

        // ---- POST /verify-checkout — the merchant's half of AP2 ----
        // Body: { openCheckoutPresentation, closedCheckoutPresentation, checkoutJwt,
        //         userPubkey?, kb?: { kbJwt, nonce, aud? } }
        // The mandates cross the wire as SD-JWT presentation strings. The user key is
        // the enrolment trust anchor: the one configured at start() wins, the body
        // value is only a fallback for callers that were not provisioned with it.
        if (req.method === 'POST' && pathname === '/verify-checkout') {
            try {
                const body = await readJSON(req);
                const {
                    openCheckoutPresentation, closedCheckoutPresentation,
                    checkoutJwt, kb,
                } = body || {};
                if (!closedCheckoutPresentation || !checkoutJwt) {
                    return sendJSON(res, 400, { error: 'Missing closedCheckoutPresentation or checkoutJwt' });
                }
                const record = issued.get(checkoutJwt);
                if (!record) {
                    return sendJSON(res, 404, { error: 'Unknown checkout JWT' });
                }
                const mk = merchantKeys[record.merchantId];
                const anchor = userPubkey || (body && body.userPubkey) || null;
                const checks = verify.verifyCheckoutMandates({
                    openCheckoutPresentation,
                    closedCheckoutPresentation,
                    checkoutJwt,
                    merchantCheckoutHash: record.checkoutHash,
                    userPubkey: anchor,
                    merchantId: record.merchantId,
                    kb,
                });
                // The Checkout Receipt is a JWS issued by this merchant. `reference` is
                // the sd_hash of the closed Checkout presentation that was verified.
                const receiptHandle = mandate.buildCheckoutReceipt({
                    iss: mk.pk,
                    sk: mk.sk,
                    status: checks.ok ? 'Success' : 'Error',
                    reference: mandate.hashPresented(closedCheckoutPresentation),
                    orderId: checks.ok ? `order_${record.checkoutHash.slice(0, 12)}` : undefined,
                    error: checks.ok ? undefined : 'invalid_mandate',
                    errorDescription: checks.ok ? undefined : 'Closed Checkout Mandate rejected',
                });
                return sendJSON(res, checks.ok ? 200 : 403, {
                    checks,
                    receipt: receiptHandle.claims,
                    receiptJwt: receiptHandle.sdjwt,
                    receiptSignature: jwsSignatureOf(receiptHandle.sdjwt),
                });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- POST /quotes — repoint the offer prices (benchmark harness) ----
        if (req.method === 'POST' && pathname === '/quotes') {
            try {
                const body = await readJSON(req);
                if (!Array.isArray(body.quotes) || body.quotes.length === 0) {
                    return sendJSON(res, 400, { error: 'Missing quotes array' });
                }
                quotes = body.quotes.map((v) => parseInt(v, 10));
                merchantKeys = quotes.map(() => keys.generateKeypair());
                return sendJSON(res, 200, { ok: true, merchants: quotes.length });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- GET /quote/{id} — an offer ----
        const quoteMatch = pathname.match(/^\/quote\/(\d+)$/);
        if (req.method === 'GET' && quoteMatch) {
            return withQuoteLock(async () => {
                const id = parseInt(quoteMatch[1], 10);
                if (id < 0 || id >= quotes.length) return sendJSON(res, 404, { error: `Merchant ${id} not found` });
                const mk = merchantKeys[id];

                // The agent names the task and publishes the bid commitment it sent; the
                // merchant refuses to respond unless the opening matches that commitment.
                const qid = url.searchParams.get('qid');
                const bidCommitmentHex = url.searchParams.get('bidCommitment');
                const bidRaw = url.searchParams.get('bid');
                // The prototype binds the received bid to a commitment opening. Plain AP2 does
                // not, so the baseline only reads the bid and skips the opening check.
                const bidCheck = bidAttestation
                    ? checkBidOpening(bidRaw, url.searchParams.get('bidBlinding'), bidCommitmentHex)
                    : (bidRaw === null ? { ok: true, absent: true } : { ok: true, bid: parseInt(bidRaw, 10) });
                if (bidAttestation && !bidCheck.ok) return sendJSON(res, 400, { error: bidCheck.error });

                if (mode === 'sealed') {
                    const tHandler0 = performance.now();
                    const agentPubkeyHex = url.searchParams.get('agentPubkey');
                    if (!agentPubkeyHex) return sendJSON(res, 400, { error: 'Missing agentPubkey' });
                    const n = parseInt(url.searchParams.get('n') || '32', 10);

                    // Merchant response strategy. The protocol does not constrain it; the
                    // experiments fix it explicitly. Under 'reject-below-price' a merchant
                    // declines a quote that does not cover its price and signs a rejection
                    // carrying the quote commitment. Under the default it always offers.
                    if (responseStrategy === 'reject-below-price'
                        && bidCheck.bid !== undefined && bidCheck.bid < quotes[id]) {
                        const attest = await signAndSubmit({
                            qid, id, bidCommitment: bidCommitmentHex, kind: 'rejection', offer: null,
                        });
                        return sendJSON(res, 200, {
                            id, rejected: true, bid: bidCheck.bid, ...(attest || {}),
                        });
                    }
                    try {
                        const agentPk = h2p(agentPubkeyHex);
                        const tCommit0 = performance.now();
                        const r = c.randomBlind();
                        const cmt = c.commit(r, quotes[id]);
                        const tCommitMs = performance.now() - tCommit0;
                        const plain = JSON.stringify({ value: String(quotes[id]), blinding: r.toString('hex') });
                        const tEncrypt0 = performance.now();
                        const sealed = await ecies.encrypt(agentPk, plain);
                        const tEncryptMs = performance.now() - tEncrypt0;
                        const { proof: priceProof, timingMs: priceTiming } = generatePriceProof(quotes[id], r, n);
                        const commitment = c.commitToHex(cmt);

                        const payload = buildCheckoutPayload(id, mode, { commitment });
                        // The checkout JWT is a JWS compact string signed with the merchant
                        // key; checkout_hash is base64url(SHA-256(that exact JWS)).
                        const tSign0 = performance.now();
                        const checkoutJwt = sdjwt.signJws(payload, mk.sk);
                        const tCheckoutSignMs = performance.now() - tSign0;
                        const checkoutHash = checkoutHashOf(checkoutJwt);
                        issued.set(checkoutJwt, { merchantId: id, checkoutHash });

                        const attest = await signAndSubmit({
                            qid, id, bidCommitment: bidCommitmentHex, kind: 'offer',
                            offer: { commitment, sealed, priceProof, checkoutJwt, checkoutHash },
                            n,
                        });

                        sendJSON(res, 200, {
                            id,
                            merchant: merchantObject(id),
                            merchantPubkey: mk.pk,
                            commitment,
                            sealed,
                            priceProof,
                            tCommitMs: +tCommitMs.toFixed(2),
                            tEncryptMs: +tEncryptMs.toFixed(2),
                            tHandlerMs: +(performance.now() - tHandler0).toFixed(2),
                            tRecvMs: tRecv,
                            tHandlerStartMs: +(tHandler0 - merchantT0).toFixed(1),
                            tEndMs: +(performance.now() - merchantT0).toFixed(1),
                            tCheckoutSignMs: +tCheckoutSignMs.toFixed(2),
                            tPriceProofMs: +(priceTiming.min + priceTiming.max).toFixed(1),
                            tPriceProofMin: priceTiming.min || null,
                            tPriceProofMax: priceTiming.max || null,
                            checkoutJwt,
                            checkoutHash,
                            checkoutPayload: payload,
                            ...(attest || {}),
                            checkoutSignature: jwsSignatureOf(checkoutJwt),
                        });
                    } catch (e) {
                        sendJSON(res, 400, { error: e.message });
                    }
                } else {
                    // Plain mode — optional bidding round: a merchant rejects a buyer bid
                    // below its ask price. Without ?bid the merchant always quotes.
                    if (bidCheck.bid !== undefined && bidCheck.bid < quotes[id]) {
                        const attest = await signAndSubmit({
                            qid, id, bidCommitment: bidCommitmentHex, kind: 'rejection', offer: null,
                        });
                        return sendJSON(res, 200, {
                            id, rejected: true, bid: bidCheck.bid, ...(attest || {}),
                        });
                    }

                    // Full checkout generation: payload, JWS signature, and the hash the
                    // mandate binds. Measured as one block so a caller can attribute the
                    // whole per-merchant cost (not just the ECDSA part).
                    const tGen0 = performance.now();
                    const payload = buildCheckoutPayload(id, mode, { quote: quotes[id] });
                    const tSign0 = performance.now();
                    const checkoutJwt = sdjwt.signJws(payload, mk.sk);
                    const tCheckoutSignMs = performance.now() - tSign0;
                    const checkoutHash = checkoutHashOf(checkoutJwt);
                    const tCheckoutGenMs = performance.now() - tGen0;
                    issued.set(checkoutJwt, { merchantId: id, checkoutHash });

                    const attest = await signAndSubmit({
                        qid, id, bidCommitment: bidCommitmentHex, kind: 'offer',
                        offer: { quote: quotes[id], checkoutJwt, checkoutHash },
                    });

                    sendJSON(res, 200, {
                        id,
                        merchant: merchantObject(id),
                        merchantPubkey: mk.pk,
                        quote: quotes[id],
                        tCheckoutSignMs: +tCheckoutSignMs.toFixed(2),
                        tCheckoutGenMs: +tCheckoutGenMs.toFixed(2),
                        checkoutJwt,
                        checkoutHash,
                        checkoutPayload: payload,
                        ...(attest || {}),
                        checkoutSignature: jwsSignatureOf(checkoutJwt),
                    });
                }
                return;
            });
        }

        // ---- GET /pubkey/{id} ----
        const pkMatch = pathname.match(/^\/pubkey\/(\d+)$/);
        if (req.method === 'GET' && pkMatch) {
            const id = parseInt(pkMatch[1], 10);
            if (id < 0 || id >= quotes.length) return sendJSON(res, 404, { error: `Merchant ${id} not found` });
            return sendJSON(res, 200, {
                merchantId: id,
                signingPubkey: merchantKeys[id].pk,
            });
        }

        // ---- GET /health ----
        if (req.method === 'GET' && pathname === '/health') {
            sendJSON(res, 200, {
                ok: true,
                mode,
                quotes,
                merchants: quotes.map((_, i) => merchantObject(i)),
                merchantPubkeys: merchantKeys.map((k) => k.pk),
            });
            return;
        }

        if (req.method === 'GET') return serveStatic(WEB_ROOT, decodeURIComponent(pathname), res);

        sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3110;
    const mode = opts.mode || 'sealed';
    const quotes = opts.quotes || [120, 95, 150, 130];
    const userPubkey = opts.userPubkey || null;
    const providerUrl = opts.providerUrl || null;
    const bidAttestation = opts.bidAttestation === true;
    const responseStrategy = opts.responseStrategy || 'always-offer';
    const handler = createHandler({ mode, quotes, userPubkey, providerUrl, bidAttestation, responseStrategy });
    const server = http.createServer(handler);
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`✓ Merchant Server [${mode}]: http://localhost:${port}  quotes=${quotes.join(',')}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('./common/http-utils');
    const port = parseInt(getArg(process.argv, '--port', '3110'), 10);
    const mode = getArg(process.argv, '--mode', 'sealed');
    const quotesStr = getArg(process.argv, '--quotes', '120,95,150,130');
    const quotes = quotesStr.split(',').map((s) => parseInt(s.trim(), 10));
    const userPubkey = getArg(process.argv, '--user-pubkey', null);
    const providerUrl = getArg(process.argv, '--provider-url', null);
    const bidAttestation = getArg(process.argv, '--bid-attestation', mode === 'sealed' ? 'true' : 'false') === 'true';
    start({ port, mode, quotes, userPubkey, providerUrl, bidAttestation });
}

module.exports = { start, createHandler };
