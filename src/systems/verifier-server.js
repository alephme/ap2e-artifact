// Verifier Server — independent third-party verification for the range-proof
// prototype (AP2-E).
//
//   GET  /nonce            { nonce, aud, expiresInSec }   — single-use, 60 s TTL
//   POST /verify           { publicData, n }            — zero-knowledge proofs only
//   POST /verify-mandate   { ...Presentations, publicData, n, kb } — mandate chain + ZK proofs
//
// The mandate half reuses the same role checks the Merchant and Credential Provider
// run (src/mandates/ap2-verify.js), and the zero-knowledge verdict feeds the
// `payment.amount_range_committed` constraint: the cap is hidden, so the only way to
// evaluate it is to verify the range proofs that relate the selected amount to the
// committed cap.
//
// Key binding: the verifier is the nonce issuer. The agent fetches a nonce from
// GET /nonce and attaches a kb-sd-jwt (src/mandates/sdjwt.js) to each presentation it
// forwards. A nonce is single use and expires after NONCE_TTL_SEC; the kb is checked
// against the nonce record, the presentation it was built over (sd_hash) and, when
// the nonce was requested for an audience, that audience.

const http = require('http');
const { randomBytes } = require('crypto');
const { sendJSON, readJSON, cors } = require('./common/http-utils');
const { verifyDecision, verifyPriceValidityResponse } = require('../shopping/verifier');
const mandateVerify = require('../mandates/ap2-verify');
const { hexToPoint } = require('../shopping/commitments');
const eqproof = require('../crypto/eqproof');
const { base64url } = require('../mandates/hashes');
const keys = require('../mandates/keys');

const MAX_BODY = 64 * 1024 * 1024;
const NONCE_TTL_SEC = 60;

// Placeholder expected nonce for a kb whose nonce was never issued (or was already
// used): it can never match the value inside the kb, so the kb check fails closed.
const INVALID_NONCE = '__nonce_not_issued__';

function flatten(prefix, obj) {
    const out = [];
    for (const [k, v] of Object.entries(obj || {})) {
        if (k === 'ok') continue;
        out.push({ step: `${prefix}.${k}`, pass: v === true, reason: v === true ? 'ok' : 'failed' });
    }
    return out;
}

// ---- single-use nonce store ----

function createNonceStore() {
    const records = new Map();
    const now = () => Date.now();

    function prune() {
        for (const [nonce, record] of records) {
            if (record.expiresAt <= now()) records.delete(nonce);
        }
    }

    return {
        issue(aud) {
            prune();
            const nonce = base64url(randomBytes(16));
            records.set(nonce, {
                aud: typeof aud === 'string' && aud.length > 0 ? aud : null,
                expiresAt: now() + NONCE_TTL_SEC * 1000,
            });
            return nonce;
        },
        // Single use: the record is removed the first time it is taken. Returns
        // { nonce, aud } or null when the nonce is unknown, used or expired.
        take(nonce) {
            prune();
            const record = records.get(nonce);
            if (!record) return null;
            records.delete(nonce);
            return { nonce, aud: record.aud };
        },
    };
}

// ---- task records ----
// The credential provider's own view of a purchase round: which merchants were
// registered, which merchant-signed responses arrived before the deadline, and
// whether any merchant sent conflicting responses. Verification reads this store,
// never the agent's account of it, so "agent-supplied alternatives cannot replace
// these inputs" (paper, Appendix B).
function createTaskStore() {
    const tasks = new Map(); // qid -> task

    function canonical(obj) {
        return JSON.stringify(obj, Object.keys(obj).sort());
    }

    return {
        register(qid, merchants, groups) {
            const existing = tasks.get(qid);
            if (existing && existing.fixed) return { ok: false, error: 'task already fixed' };
            const table = new Map();
            for (const m of merchants || []) {
                if (!m || m.id === undefined || typeof m.pubkey !== 'string') continue;
                table.set(String(m.id), m.pubkey);
            }
            tasks.set(qid, {
                merchants: table,
                groups: groups || [],
                responses: new Map(),
                conflicts: new Set(),
                fixed: false,
                fixedAt: null,
                priceValidityMs: 0,
                priceValidityOk: 0,
                priceValidityBad: 0,
                priceValidityDone: false,
            });
            return { ok: true, merchants: table.size };
        },

        get(qid) { return tasks.get(qid) || null; },

        // A merchant submits one signed response. Identical retransmissions are
        // counted once; two different responses from the same merchant conflict.
        submit(qid, response, signature) {
            const task = tasks.get(qid);
            if (!task) return { ok: false, error: 'unknown task' };
            if (task.fixed) return { ok: false, error: 'response set already fixed' };
            if (!response || String(response.qid) !== String(qid)) {
                return { ok: false, error: 'response is not bound to this task' };
            }
            const mid = String(response.merchantId);
            const pk = task.merchants.get(mid);
            if (!pk) return { ok: false, error: 'merchant not registered for this task' };
            if (typeof signature !== 'string' || !keys.verify(keys.hashJSON(response), signature, pk)) {
                return { ok: false, error: 'invalid merchant signature' };
            }
            const prior = task.responses.get(mid);
            if (prior) {
                if (canonical(prior.response) === canonical(response)) return { ok: true, duplicate: true };
                task.conflicts.add(mid);
                return { ok: false, error: 'conflicting responses from the same merchant' };
            }
            const stored = { response, signature, at: Date.now() };
            task.responses.set(mid, stored);
            return { ok: true, stored: task.responses.size };
        },

        fix(qid) {
            const task = tasks.get(qid);
            if (!task) return { ok: false, error: 'unknown task' };
            const registered = [...task.merchants.keys()].sort();
            // Submissions travel in parallel with the merchant's answer to the agent, so
            // a fix request can arrive before the last one lands. Report what is still
            // outstanding instead of freezing an incomplete set.
            const missing = registered.filter((id) => !task.responses.has(id));
            if (missing.length > 0 || task.conflicts.size > 0) {
                return {
                    ok: false,
                    qid,
                    pending: missing.length,
                    conflicts: [...task.conflicts],
                    registered,
                    responses: [...task.responses.keys()].sort(),
                };
            }
            task.fixed = true;
            task.fixedAt = Date.now();
            return {
                ok: true,
                qid,
                fixedAt: task.fixedAt,
                registered,
                responses: registered.slice(),
                conflicts: [],
                priceValidityMs: +task.priceValidityMs.toFixed(2),
                priceValidityVerified: task.priceValidityOk,
            };
        },

        summary(qid) {
            const task = tasks.get(qid);
            if (!task) return null;
            return {
                qid,
                fixed: task.fixed,
                registered: [...task.merchants.keys()].sort(),
                responses: [...task.responses.entries()].map(([mid, r]) => ({
                    merchantId: mid,
                    kind: r.response.kind,
                    bidCommitment: r.response.bidCommitment,
                })),
                conflicts: [...task.conflicts],
            };
        },

        // Completeness: every registered merchant has exactly one valid response and
        // no merchant sent conflicting ones. Returns the ids when complete, else null.
        completeIds(qid) {
            const task = tasks.get(qid);
            if (!task) return null;
            const registered = [...task.merchants.keys()].sort();
            const answered = [...task.responses.keys()].sort();
            const same = registered.length > 0
                && registered.length === answered.length
                && registered.every((v, i) => v === answered[i]);
            if (!same || task.conflicts.size > 0) return null;
            return registered;
        },

        // Price validity is checked at the deadline, after the merchant block ends, so the
        // time it takes is visible on its own rather than hidden inside the merchant phase.
        notePriceValidity(qid, ms, ok) {
            const task = tasks.get(qid);
            if (!task) return;
            task.priceValidityMs = ms;
            task.priceValidityDone = true;
            task.priceValidityBad = ok ? 0 : 1;
        },

        priceValidityCount(qid) {
            const task = tasks.get(qid);
            return task ? [...task.responses.values()].filter((r) => {
                const offer = r.response && r.response.offer;
                return !!(offer && offer.commitment && offer.priceProof);
            }).length : 0;
        },

        priceValidityTargets(qid) {
            const task = tasks.get(qid);
            if (!task) return [];
            return [...task.responses.values()]
                .map((r) => r.response || {})
                .filter((response) => {
                    const offer = response.offer;
                    return !!(offer && offer.commitment && offer.priceProof);
                })
                .map((response) => ({
                    commitment: response.offer.commitment,
                    priceProof: response.offer.priceProof,
                    n: response.n || 32,
                }));
        },

        priceValidityAtCollection(qid) {
            const task = tasks.get(qid);
            if (!task) return { ms: 0, allVerified: false };
            return {
                ms: +task.priceValidityMs.toFixed(2),
                allVerified: task.priceValidityDone === true && task.priceValidityBad === 0,
            };
        },
    };
}

function createHandler({ userPubkey } = {}) {
    const nonceStore = createNonceStore();
    const taskStore = createTaskStore();

    // Normalise a kb-sd-jwt object for ap2-verify. The expected nonce comes from the
    // store, never from the request body, so an unissued or reused nonce cannot pass.
    // `taken` is the per-request record of consumed nonces: one nonce may bind the kb
    // of more than one presentation when they are verified in the same request.
    function bindKb(entry, taken) {
        if (!entry || typeof entry !== 'object') return undefined;
        let record = null;
        if (typeof entry.nonce === 'string' && entry.nonce.length > 0) {
            record = taken.get(entry.nonce) || null;
            if (!record) {
                record = nonceStore.take(entry.nonce);
                if (record) taken.set(entry.nonce, record);
            }
        }
        return {
            kbJwt: entry.kbJwt,
            nonce: record ? record.nonce : INVALID_NONCE,
            // When the nonce was issued for an audience, that audience is mandatory.
            aud: record && record.aud ? record.aud : entry.aud,
            presentation: entry.presentation,
        };
    }

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        const url = new URL(req.url, 'http://localhost');

        // ---- GET /nonce — a single-use key-binding nonce ----
        if (req.method === 'GET' && url.pathname === '/nonce') {
            const aud = url.searchParams.get('aud') || undefined;
            return sendJSON(res, 200, {
                nonce: nonceStore.issue(aud),
                aud: aud || null,
                expiresInSec: NONCE_TTL_SEC,
            });
        }

        // ---- POST /register-task — the merchant scope, registered before bidding ----
        if (req.method === 'POST' && url.pathname === '/register-task') {
            try {
                const { qid, merchants, groups } = await readJSON(req);
                if (!qid || !Array.isArray(merchants)) {
                    return sendJSON(res, 400, { error: 'Missing qid or merchants' });
                }
                return sendJSON(res, 200, taskStore.register(qid, merchants, groups));
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- POST /submit — a merchant submits its signed response (offer or rejection) ----
        if (req.method === 'POST' && url.pathname === '/submit') {
            try {
                const { qid, response, signature } = await readJSON(req);
                if (!qid || !response) return sendJSON(res, 400, { error: 'Missing qid or response' });
                const result = taskStore.submit(qid, response, signature);
                return sendJSON(res, result.ok ? 200 : 403, result);
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- POST /fix — close the response set at the deadline ----
        // The protocol gives merchants a window to deliver; the set is fixed at the end
        // of that window. In our experiments every response arrives well before it, so
        // the wait is normally zero.
        if (req.method === 'POST' && url.pathname === '/fix') {
            try {
                const { qid, graceMs } = await readJSON(req);
                if (!qid) return sendJSON(res, 400, { error: 'Missing qid' });
                const window = Math.max(0, Math.min(Number(graceMs) || 0, 5000));
                const deadline = Date.now() + window;
                let result = taskStore.fix(qid);
                while (!result.ok && result.pending > 0 && Date.now() < deadline) {
                    await new Promise((r) => setTimeout(r, 5));
                    result = taskStore.fix(qid);
                }
                // The price-validity arguments are checked now, at the deadline, once the
                // merchant block is over. Doing it earlier would hide this provider work
                // inside the merchant phase, where dividing by the merchant count would
                // compress it away.
                if (result.ok) {
                    let ms = 0;
                    let bad = 0;
                    for (const entry of taskStore.priceValidityTargets(qid)) {
                        const pv = verifyPriceValidityResponse(
                            entry.commitment, entry.priceProof, entry.n);
                        ms += pv.ms;
                        if (!pv.ok) bad += 1;
                    }
                    taskStore.notePriceValidity(qid, ms, bad === 0);
                    result.priceValidityMs = +ms.toFixed(2);
                    result.priceValidityVerified = taskStore.priceValidityCount(qid) - bad;
                    result.priceValidityFailed = bad;
                }
                return sendJSON(res, result.ok ? 200 : 404, result);
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- GET /task?qid=... — the collected set, for diagnostics ----
        if (req.method === 'GET' && url.pathname === '/task') {
            const qid = url.searchParams.get('qid');
            const summary = qid ? taskStore.summary(qid) : null;
            return summary ? sendJSON(res, 200, summary) : sendJSON(res, 404, { error: 'unknown task' });
        }

        // ---- ZKP-only verification ----
        if (req.method === 'POST' && url.pathname === '/verify') {
            try {
                const body = await readJSON(req, MAX_BODY);
                const { publicData, n } = body;
                if (!publicData || !publicData.commitments || publicData.removed === undefined) {
                    return sendJSON(res, 400, { error: 'Missing required fields: publicData' });
                }
                return sendJSON(res, 200, verifyDecision(publicData, n || 32));
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        // ---- Mandate-bound verification ----
        if (req.method === 'POST' && url.pathname === '/verify-mandate') {
            try {
                const body = (await readJSON(req, MAX_BODY)) || {};
                const {
                    openCheckoutPresentation, openPaymentPresentation,
                    closedCheckoutPresentation, closedPaymentPresentation,
                    checkoutJwt, merchantCheckoutHash, merchantId,
                    publicData, n,
                    registeredMerchants, bidConsistency,
                    qid,
                } = body;
                const N = n || 32;
                const tStart = performance.now();
                const taken = new Map();

                // The user key is the enrolment trust anchor: the configured key wins,
                // the body value is only a fallback.
                const anchor = userPubkey || body.userPubkey || null;
                const kbSrc = body.kb && typeof body.kb === 'object' ? body.kb : {};
                const kbCheckout = bindKb(kbSrc.checkout, taken);
                const kbPayment = bindKb(kbSrc.payment, taken);

                // ---- response accounting (AP2-E) ----
                // The provider's own record decides what the response set is: every
                // registered merchant must have exactly one signed response and no
                // merchant may have sent conflicting ones. The agent's account of the
                // set is used only when no task was registered (standalone proofs).
                const tAcct0 = performance.now();
                const task = qid ? taskStore.get(qid) : null;
                // The agent's committed seller set must equal the set of merchants whose
                // stored response is an offer, and the provider's own store must hold a
                // response from every registered merchant. Comparing the store with itself
                // would never catch an agent that silently drops an offer from the evidence.
                const sellers = ((publicData && publicData.commitments
                    && publicData.commitments.sellers) || [])
                    .map((s) => Number(s.i)).sort((a, b) => a - b);
                const registered = (task
                    ? [...task.merchants.keys()].map(Number)
                    : (registeredMerchants || []).map(Number)).slice().sort((a, b) => a - b);
                const offerIds = task
                    ? [...task.responses.values()]
                        .filter((r) => r.response && r.response.kind === 'offer')
                        .map((r) => Number(r.response.merchantId))
                        .sort((a, b) => a - b)
                    : sellers;
                const storedIds = task ? taskStore.completeIds(qid) : null;
                const storeComplete = task
                    ? !!(storedIds && storedIds.length === registered.length)
                    : true;
                const acctOk = storeComplete
                    && offerIds.length > 0
                    && sellers.length === offerIds.length
                    && sellers.every((v, i) => v === offerIds[i]);
                const tAccounting = performance.now() - tAcct0;

                // 1. Zero-knowledge proofs over the published commitments.
                const tZkp0 = performance.now();
                let zkpResult = { allPass: false };
                // Without a deadline the provider closes the set itself: every registered
                // merchant has answered, and the evidence has arrived, so the price-validity
                // arguments are checked here, once, before the evidence is verified.
                if (task && !task.priceValidityDone) {
                    let pvMs = 0;
                    let pvBad = 0;
                    for (const entry of taskStore.priceValidityTargets(qid)) {
                        const pv = verifyPriceValidityResponse(
                            entry.commitment, entry.priceProof, entry.n);
                        pvMs += pv.ms;
                        if (!pv.ok) pvBad += 1;
                    }
                    taskStore.notePriceValidity(qid, pvMs, pvBad === 0);
                }
                const pvAtCollection = task ? taskStore.priceValidityAtCollection(qid) : { ms: 0, allVerified: false };
                if (acctOk && publicData && publicData.commitments && publicData.removed !== undefined) {
                    try {
                        zkpResult = verifyDecision(publicData, N, { skipPriceValidity: pvAtCollection.allVerified });
                    } catch (err) {
                        zkpResult = { allPass: false, error: err.message };
                    }
                }
                const tZkp = performance.now() - tZkp0;
                const zkpVerified = !!zkpResult.allPass;

                // 2. The checkout half, as the Merchant would check it.
                // 3. The payment half, as the Credential Provider would check it, with
                //    the committed-cap constraint evaluated by the ZK verdict.
                const tMand0 = performance.now();
                const checkoutChecks = mandateVerify.verifyCheckoutMandates({
                    openCheckoutPresentation,
                    closedCheckoutPresentation,
                    checkoutJwt,
                    merchantCheckoutHash,
                    userPubkey: anchor,
                    merchantId,
                    kb: kbCheckout,
                });
                const paymentChecks = mandateVerify.verifyPaymentMandates({
                    openPaymentPresentation,
                    closedPaymentPresentation,
                    openCheckoutPresentation,
                    userPubkey: anchor,
                    zkpVerified,
                    kb: kbPayment,
                });
                const tMandates = performance.now() - tMand0;

                const checks = [
                    ...flatten('checkout', checkoutChecks),
                    ...flatten('payment', paymentChecks),
                ];

                // ---- bid consistency (AP2-E) ----
                // The agent publishes a commitment per merchant to the buyer bid it sent,
                // plus n-1 equality proofs. All commitments must open to the same value.
                const tBid0 = performance.now();
                let bidOk = false;
                let bidReason = 'missing bid-consistency evidence';
                if (bidConsistency && Array.isArray(bidConsistency.entries)) {
                    try {
                        const entries = bidConsistency.entries.map((e) => ({
                            Ba: hexToPoint(e.Ba),
                            Bi: hexToPoint(e.Bi),
                            proof: eqproof.eqProofFromJSON(e.proof),
                            ctx: { groupId: 1, aId: e.aId, iId: e.iId },
                        }));
                        bidOk = entries.length > 0 && eqproof.batchVerifyEq(entries);
                        bidReason = bidOk
                            ? 'all bid commitments open to the same value'
                            : 'bid commitments do not open to the same value';
                    } catch (err) {
                        bidOk = false;
                        bidReason = `malformed bid evidence: ${err.message}`;
                    }
                }
                const tBidVerify = performance.now() - tBid0;
                checks.push({ step: 'bid.consistency', pass: bidOk, reason: bidReason });

                // ---- bid acknowledgement (AP2-E) ----
                // Equality proofs show that the commitments the agent published open to
                // one value; they say nothing about the commitment each merchant actually
                // received. When the provider holds the collected responses, the
                // published commitments must be the attested ones.
                const tAck0 = performance.now();
                if (task) {
                    let ackOk = !!(bidConsistency && Array.isArray(bidConsistency.entries));
                    if (ackOk) {
                        const published = new Map();
                        for (const e of bidConsistency.entries) {
                            published.set(String(e.iId), String(e.Bi));
                            published.set(String(e.aId), String(e.Ba));
                        }
                        for (const [mid, rec] of task.responses) {
                            const attested = rec.response && rec.response.bidCommitment;
                            if (!attested || published.get(String(mid)) !== String(attested)) {
                                ackOk = false;
                                break;
                            }
                        }
                    }
                    checks.push({
                        step: 'bid.acknowledged',
                        pass: ackOk,
                        reason: ackOk
                            ? 'published bid commitments match the merchant attestations'
                            : 'published bid commitments differ from what merchants attest',
                    });
                }
                const tBidAck = performance.now() - tAck0;

                // ---- response accounting (AP2-E) ----
                checks.push({
                    step: 'response.accounting',
                    pass: acctOk,
                    reason: acctOk
                        ? 'every registered merchant is accounted for'
                        : `committed set [${sellers}] does not match registered [${registered}]`,
                });
                checks.push({ step: 'zkp.proofs', pass: zkpVerified,
                    reason: zkpVerified ? 'All range proofs verified'
                        : `Range-proof verification failed${zkpResult.error ? ': ' + zkpResult.error : ''}` });

                return sendJSON(res, 200, {
                    allPass: checks.every((c) => c.pass),
                    checks,
                    zkpVerified,
                    zkpResult,
                    timingMs: {
                        total: +(performance.now() - tStart).toFixed(2),
                        mandates: +tMandates.toFixed(2),
                        zkp: +tZkp.toFixed(2),
                        bidVerify: +tBidVerify.toFixed(2),
                        bidAck: +tBidAck.toFixed(2),
                        accounting: +tAccounting.toFixed(2),
                        priceValidityAtCollection: +pvAtCollection.ms.toFixed(2),
                    },
                });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message });
            }
        }

        if (req.method === 'GET' && url.pathname === '/health') {
            return sendJSON(res, 200, { ok: true });
        }

        return sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3190;
    const server = http.createServer(createHandler({ userPubkey: opts.userPubkey || null }));
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`✓ Verifier Server: http://localhost:${port}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('./common/http-utils');
    start({
        port: parseInt(getArg(process.argv, '--port', '3190'), 10),
        userPubkey: getArg(process.argv, '--user-pubkey', null),
    });
}

module.exports = { start, createHandler };
