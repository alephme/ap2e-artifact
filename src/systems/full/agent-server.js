// Full System Agent Server (AP2 + ZKP), SD-JWT transport.
//
// Programmatic: const { start } = require('./agent-server'); start({ port, merchantUrl, verifierUrl, providerUrl, mppUrl });
// CLI:          node src/systems/full/agent-server.js --port PORT --merchant-url URL --verifier-url URL --provider-url URL --mpp-url URL
//
// The AP2 mandates travel as SD-JWT presentations (docs/sdjwt-contract.md 搂3): the
// User issues the open mandates, the Agent issues the closed ones, and every role
// verifies presentation strings against explicit trust anchors. The Verifier is the
// nonce issuer: before each verification call the Agent fetches a single-use nonce
// (GET /nonce) and attaches a kb-sd-jwt over the presentation it forwards, signed by
// the agent key endorsed in the open mandate `cnf`.
//
// The zero-knowledge half is unchanged: the agent decrypts the sealed cap and the
// sealed offer envelopes, builds the classification/optimality range proofs plus the
// bid-consistency equality proofs, and publishes only commitments, the decision and
// the proofs.

const http = require('http');
const path = require('path');
const Agent = require('../../shopping/agent');
const { verifyDecision } = require('../../shopping/verifier');
const ecies = require('../../crypto/ecies');
const keys = require('../../mandates/keys');
const mandate = require('../../mandates/mandate');
const sdjwt = require('../../mandates/sdjwt');
const { jwkToPub } = require('../../mandates/jwk');
const c = require('../../crypto/c-backend');
const { pointToHex, randomCommit } = require('../../shopping/commitments');
const bn128 = require('../../crypto/bn128');
const eqproof = require('../../crypto/eqproof');
const { sendJSON, readJSON, cors, serveStatic } = require('../common/http-utils');
const { decisionFromSelection } = require('../../llm/decision');

// ZKP_MODE: 'single' (only mode wired to the C backend; 'aggregated' is not wired).
const ZKP_MODE = process.env.ZKP_MODE || 'single';

const WEB_ROOT = path.join(__dirname, '..', '..', 'web');

// Claims an open mandate must disclose before anyone can evaluate it.
const OPEN_REQUIRED = ['vct', 'iss', 'constraints', 'cnf', 'iat', 'exp'];

// Audience strings for the kb-sd-jwt `aud` claim; the verifier records the audience
// when it issues the nonce, so the binding is checked against the same value.
const AUD = {
    verifier: 'verifier',
    cp: 'credential-provider',
    mpp: 'merchant-payment-processor',
    merchant: 'merchant',
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

// ---- C-backend difference proofs (single mode): one range proof per difference ----
// removed (infeasible): d = b_i 鈭?w 鈭?1, D = B_i 鈭?W 鈭?g, blinding rD = r_i 鈭?r_w
// feasible            : d = w 鈭?b_i,      D = W 鈭?B_i,     blinding rD = r_w 鈭?r_i
// optimality          : d = b_j 鈭?b_c,    D = B_j 鈭?B_c,   blinding rD = r_j 鈭?r_c
function buildDiffProofsC(agent, decision, n, opts = {}) {
    const { removed, chosen } = decision;
    const infeasibleProofs = {}, feasibleProofs = {}, optimalityProofs = {};
    const g = c.generators().value;                 // value_gen (the commitment to 1)
    let tInfeasibleMs = 0, tFeasibleMs = 0;
    const quotes = agent.quotes, limit = agent.limit;
    const rLim = c.fromHex(limit.blindingHex);

    // A difference the agent would have to prove can be negative (it picked an
    // over-limit offer, or a non-cheapest one). An honest agent cannot prove it; a
    // malicious agent does not give up 鈥?it submits a decoy proof for a different
    // statement and lets the verifier reject it. `forge` selects the second behaviour.
    const proveDiff = (diffValue, blinding) => {
        try {
            const d = c.rangeCheck(diffValue, n);
            return c.toHex(c.prove(d, blinding, n).proof);
        } catch (e) {
            if (!opts.forge) throw e;
            const decoy = c.rangeCheck(0, n);
            return c.toHex(c.prove(decoy, c.randomBlind(), n).proof);
        }
    };

    for (let i = 0; i < quotes.length; i++) {
        const qi = quotes[i];
        if (!qi) continue; // rejection: no offer, so no classification
        const t0 = performance.now();
        if (removed.includes(i)) {
            const rD = c.blindSum([c.fromHex(qi.blindingHex), rLim, c.ZERO_BLIND], 1, n);
            infeasibleProofs[i] = proveDiff(qi.valueInt - limit.valueInt - 1, rD);
            tInfeasibleMs += performance.now() - t0;
        } else if (i !== chosen) {
            // The selected offer is not classified: its price is disclosed in the signed
            // checkout and enforced by the payment mandate, so the protocol checks it
            // directly instead of asking for a Classify argument.
            const rD = c.blindSum([rLim, c.fromHex(qi.blindingHex)], 1, n);
            feasibleProofs[i] = proveDiff(limit.valueInt - qi.valueInt, rD);
            tFeasibleMs += performance.now() - t0;
        }
    }
    const tOpt0 = performance.now();
    if (chosen !== null) {
        const cq = quotes[chosen];
        for (let j = 0; j < quotes.length; j++) {
            if (j === chosen || removed.includes(j) || !quotes[j]) continue;
            const rD = c.blindSum([c.fromHex(quotes[j].blindingHex), c.fromHex(cq.blindingHex)], 1, n);
            optimalityProofs[j] = proveDiff(quotes[j].valueInt - cq.valueInt, rD);
        }
    }
    const tOptimalityMs = performance.now() - tOpt0;
    const total = tInfeasibleMs + tFeasibleMs + tOptimalityMs;
    return {
        infeasibleProofs, feasibleProofs, optimalityProofs,
        timingMs: {
            infeasible: +tInfeasibleMs.toFixed(1),
            feasible: +tFeasibleMs.toFixed(1),
            optimality: +tOptimalityMs.toFixed(1),
            prove: +total.toFixed(1),
        },
    };
}

function createHandler({ merchantUrl, verifierUrl, providerUrl, mppUrl }) {
    let session = null;

    function ensureSession() {
        if (!session) {
            const agentKp = keys.generateKeypair();
            const zkpAgent = Agent.generate();
            session = {
                agentKp,
                agent: zkpAgent,
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

    // kb object for the CP/MPP: { kbJwt, nonce, aud } over the forwarded presentation.
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

    // The verifier checks one kb per presentation in the same request: both entries
    // share a single nonce (the verifier consumes it once and reuses the record for
    // the second presentation) and name the presentation they bind.
    async function verifierKeyBindings({ closedCheckoutPresentation, closedPaymentPresentation, holderSk, warnings }) {        if (!closedCheckoutPresentation && !closedPaymentPresentation) return undefined;
        try {
            const { nonce, aud } = await fetchNonce(AUD.verifier);
            const kb = {};
            if (closedCheckoutPresentation) {
                kb.checkout = {
                    kbJwt: sdjwt.buildKbJwt({ presentation: closedCheckoutPresentation, nonce, aud, holderSk }),
                    nonce, aud, presentation: 'closedCheckout',
                };
            }
            if (closedPaymentPresentation) {
                kb.payment = {
                    kbJwt: sdjwt.buildKbJwt({ presentation: closedPaymentPresentation, nonce, aud, holderSk }),
                    nonce, aud, presentation: 'closedPayment',
                };
            }
            return kb;
        } catch (e) {
            warnings.push(`Key binding for verifier unavailable: ${e.message}`);
            return undefined;
        }
    }

    return async (req, res) => {
        if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

        const url = new URL(req.url, 'http://localhost');
        const pathname = url.pathname;

        // ---- GET /pubkey ----
        if (req.method === 'GET' && pathname === '/pubkey') {
            const s = ensureSession();
            return sendJSON(res, 200, {
                signingPubkey: s.agentKp.pk,
                eciesPubkey: pointToHex(s.agent.pk),
            });
        }

        // ---- POST /build-mandate 鈥?draft and sign the open mandates for the user ----
        // Body: { userPubkey, userSk, currency?, sealedMaxUnitPrice: { commitment, sealed },
        //         allowedMerchants? }
        // The caller supplies both halves of the user key: the secret key signs the open
        // SD-JWTs at build time, the public key is the trust anchor and must match it.
        if (req.method === 'POST' && pathname === '/build-mandate') {
            try {
                const body = await readJSON(req);
                const { userPubkey, userSk, currency, sealedMaxUnitPrice, allowedMerchants } = body || {};
                if (typeof userPubkey !== 'string' || userPubkey.length === 0
                    || typeof userSk !== 'string' || userSk.length === 0) {
                    return sendJSON(res, 400, { error: 'Missing userPubkey or userSk' });
                }
                if (!sealedMaxUnitPrice || !sealedMaxUnitPrice.commitment) {
                    return sendJSON(res, 400, { error: 'Missing userPubkey or sealedMaxUnitPrice' });
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
                const openPayment = mandate.buildOpenPaymentMandateCommitted({
                    userPubkey,
                    userSk,
                    agentPubkey: s.agentKp.pk,
                    currency: currency || 'USD',
                    limitCommitment: sealedMaxUnitPrice.commitment,
                    sealedLimit: sealedMaxUnitPrice.sealed,
                    allowedPayees: allowed,
                    openCheckout,
                });
                s.openCheckout = openCheckout;
                s.openPayment = openPayment;

                // Only presentation strings are handed to the caller; /execute forwards
                // them onward. The claims are returned for inspection only.
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

        // ---- POST /execute ----
        // Body: { openCheckoutPresentation, openPaymentPresentation, userPubkey?,
        //         n?, cheat?, target? }
        if (req.method === 'POST' && pathname === '/execute') {
            const tTotal = now();
            const warnings = [];
            let cpQuotes = 0, cpProve = 0, cpVerify = 0, cpIssue = 0;
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
                const N = body.n || 32;

                // Accept either the explicit presentation field or the legacy alias; the
                // value must be a presentation string, never a mandate object.
                const openCheckoutPresentation = typeof body.openCheckoutPresentation === 'string'
                    ? body.openCheckoutPresentation
                    : (typeof body.openCheckout === 'string' ? body.openCheckout : null);
                const openPaymentPresentation = typeof body.openPaymentPresentation === 'string'
                    ? body.openPaymentPresentation
                    : (typeof body.openPayment === 'string' ? body.openPayment : null);

                // 1. The open mandates: verify the user's SD-JWT signatures, recover the
                //    constrained claims, and check the agent binding (`cnf`).
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

                const checkoutAgentKey = endorsedAgentKey(openCheckout.claims);
                const paymentAgentKey = endorsedAgentKey(openPayment.claims);
                if (checkoutAgentKey !== s.agentKp.pk) {
                    return sendJSON(res, 400, { error: 'Open Checkout Mandate does not endorse this agent key' });
                }
                if (paymentAgentKey !== s.agentKp.pk) {
                    return sendJSON(res, 400, { error: 'Open Payment Mandate does not endorse this agent key' });
                }

                // 2. Extract the committed spending cap (AP2-E extension constraint).
                const sealedConstraint = (openPayment.claims.constraints || [])
                    .find((constraint) => constraint.type === 'payment.amount_range_committed');
                if (!sealedConstraint || !sealedConstraint.commitment || !sealedConstraint.sealed) {
                    return sendJSON(res, 400, { error: 'Invalid committed spending cap' });
                }

                // 3. The agent decrypts the limit (C backend: recompute the commitment and
                //    compare).
                const agent = s.agent;
                agent.quotes = [];
                agent.limit = null;
                {
                    const plain = await ecies.decrypt(agent.sk, sealedConstraint.sealed);
                    const { value, blinding } = JSON.parse(plain);
                    const valueInt = parseInt(value, 10);
                    const recomputed = c.commitToHex(c.commit(c.fromHex(blinding), valueInt));
                    if (recomputed !== sealedConstraint.commitment) {
                        warnings.push('Limit commitment mismatch');
                    }
                    agent.limit = { valueInt, blindingHex: blinding, commitment: sealedConstraint.commitment };
                }

                // 4. Query merchants (sealed mode with merchant-signed checkout JWTs).
                const healthResp = await fetch(`${merchantUrl}/health`);
                const healthData = await healthResp.json();
                const merchantCount = healthData.quotes ? healthData.quotes.length : 4;
                const merchantPubkeys = healthData.merchantPubkeys || [];

                const tQuotes0 = now();

                // ---- task registration and bid commitments (AP2-E) ----
                // The merchant scope is registered with the provider before bidding. Each
                // bid travels with its commitment and opening, so the merchant can check
                // it and attest to the commitment it received.
                const qid = `q_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
                const registeredMerchants = Array.from({ length: merchantCount }, (_, i) => i);
                const cheat = typeof body.cheat === 'string' ? body.cheat : 'none';
                const limitValue = agent.limit && Number.isFinite(agent.limit.valueInt)
                    ? agent.limit.valueInt : 500;
                // The protocol leaves the quote to the agent. A caller can fix it per
                // scenario; otherwise the agent draws one uniformly from (0, L).
                const bidValue = Number.isFinite(body.quote) && body.quote > 0
                    ? Math.floor(body.quote)
                    : 1 + Math.floor(Math.random() * Math.max(1, limitValue - 1));
                // A deviating agent quotes a lower price to the first merchant while
                // publishing commitments that open to the common value; the merchant
                // attestations expose the gap.
                const sentBids = registeredMerchants.map((i) => (
                    cheat === 'bid-equivocation' && i === 0
                        ? Math.max(1, bidValue - 10)
                        : bidValue
                ));
                const sentCommits = sentBids.map((v) => randomCommit(v));
                const bidCommits = cheat === 'bid-equivocation'
                    ? registeredMerchants.map(() => randomCommit(bidValue))
                    : sentCommits;
                try {
                    const regResp = await fetch(`${verifierUrl}/register-task`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            qid,
                            merchants: registeredMerchants.map((i) => ({ id: i, pubkey: merchantPubkeys[i] })),
                        }),
                    });
                    if (!regResp.ok) warnings.push('Task registration with the provider failed');
                } catch (e) {
                    warnings.push(`Task registration unreachable: ${e.message}`);
                }

                // Build every request before sending any. The per-merchant commitment
                // encoding is synchronous, so doing it inside the fetch loop staggers the
                // dispatches; preparing first makes all m requests leave together, which is
                // what the parallel model assumes.
                const tPrep0 = now();
                const agentPkHex = encodeURIComponent(pointToHex(agent.pk));
                const quoteUrls = [];
                for (let i = 0; i < merchantCount; i++) {
                    const sc = sentCommits[i];
                    const blindHex = sc.randomness.fromRed().toString(16);
                    const comHex = encodeURIComponent(bn128.representation(sc.point));
                    quoteUrls.push(
                        `${merchantUrl}/quote/${i}?agentPubkey=${agentPkHex}`
                        + `&n=${N}&qid=${encodeURIComponent(qid)}`
                        + `&bid=${sentBids[i]}&bidBlinding=${blindHex}`
                        + `&bidCommitment=${comHex}`,
                    );
                }
                const tQuotePrep = +(now() - tPrep0).toFixed(2);

                const quoteFetches = [];
                const quoteDurations = [];
                for (let i = 0; i < merchantCount; i++) {
                    quoteFetches.push((async () => {
                        const qf0 = now();
                        try {
                            const resp = await fetch(quoteUrls[i]);
                            const data = await resp.json();
                            quoteDurations.push(now() - qf0);
                            if (!resp.ok) throw new Error(data.error);
                            return data;
                        } catch (e) {
                            quoteDurations.push(now() - qf0);
                            warnings.push(`Merchant ${i} unreachable: ${e.message}`);
                            return null;
                        }
                    })());
                }
                const merchantResponses = (await Promise.all(quoteFetches)).filter(Boolean);

                // Close the response set at the provider. The protocol allows a delivery
                // window; in these experiments every response is already in, so the
                // provider returns immediately. The window is configurable because a run
                // with many merchants under CPU contention can leave submissions in
                // flight, and a too-short window would then refuse a valid purchase.
                // No deadline in these experiments: every registered merchant answers, so
                // the provider closes the set itself when the evidence arrives. The agent
                // does not notify it.
                let priceValidityCollectionMs = 0;
                let fixWaitMs = 0;
                const tQuotes = now() - tQuotes0;
                cpQuotes = +(now() - tTotal).toFixed(1);
                // Per-merchant checkout generation (payload + JWS + hash): max is the
                // parallel wall clock, sum the single-process serialisation artifact.
                const tCheckoutGenSum = merchantResponses.reduce((a, r) => a + (r.tCheckoutGenMs || 0), 0);
                const tCheckoutGenMax = merchantResponses.length
                    ? Math.max(...merchantResponses.map((r) => r.tCheckoutGenMs || 0)) : 0;
                // Attested response submission to the provider: max is the parallel
                // wall clock, sum the single-process serialisation artifact.
                const tSubmitSum = merchantResponses.reduce((a, r) => a + (r.tSubmitMs || 0), 0);
                const tSubmitMax = merchantResponses.length
                    ? Math.max(...merchantResponses.map((r) => r.tSubmitMs || 0)) : 0;

                // 4b. Verify each merchant's checkout JWT (JWS compact, merchant key).
                const validMerchantResponses = [];
                const rejectionResponses = [];
                for (const m of merchantResponses) {
                    const mpk = merchantPubkeys[m.id];
                    if (!mpk) {
                        warnings.push(`Merchant ${m.id}: no public key available`);
                        continue;
                    }
                    // A rejection is a valid response: it is accounted for, but it
                    // carries no offer and no price, so it is never classified or
                    // compared.
                    if (m.rejected) {
                        rejectionResponses.push(m);
                        continue;
                    }
                    const verified = sdjwt.verifyJws(m.checkoutJwt, mpk);
                    if (!verified.ok) {
                        warnings.push(`Merchant ${m.id}: invalid checkout signature 鈥?rejected`);
                        continue;
                    }
                    if (!m.checkoutPayload || verified.payload.checkout_id !== m.checkoutPayload.checkout_id) {
                        warnings.push(`Merchant ${m.id}: checkout JWT does not match the quoted checkout`);
                        continue;
                    }
                    validMerchantResponses.push(m);
                }

                // 5. Decrypt merchant envelopes (C backend: recompute the commitment).
                for (const mr of validMerchantResponses) {
                    const plain = await ecies.decrypt(agent.sk, mr.sealed);
                    const { value, blinding } = JSON.parse(plain);
                    const valueInt = parseInt(value, 10);
                    const recomputed = c.commitToHex(c.commit(c.fromHex(blinding), valueInt));
                    if (recomputed !== mr.commitment) {
                        warnings.push(`Commitment mismatch for seller ${mr.id}`);
                    }
                    agent.quotes[mr.id] = { valueInt, blindingHex: blinding, commitment: mr.commitment };
                }

                // With no recorded offer there is nothing to classify or select; the
                // purchase ends. (Rejections are already accounted for as responses.)
                if (Object.keys(agent.quotes).length === 0) {
                    throw new Error('no offer: every registered merchant returned a rejection');
                }

                // AP2-E bid-consistency evidence: one commitment per merchant that
                // answered, plus n-1 equality proofs. Rejections count: the quote that
                // drew a rejection was still delivered to that merchant and must obey the
                // same equality rule, so the evidence covers offers and rejections alike.
                const tBid0 = now();
                const respondents = [...validMerchantResponses, ...rejectionResponses]
                    .sort((a, b) => a.id - b.id);
                const published = respondents.map((r) => bidCommits[r.id] || randomCommit(bidValue));
                const bidEntries = [];
                for (let i = 1; i < published.length; i++) {
                    const ctx = { groupId: 1, aId: respondents[0].id, iId: respondents[i].id };
                    bidEntries.push({
                        aId: ctx.aId,
                        iId: ctx.iId,
                        Ba: bn128.representation(published[0].point),
                        Bi: bn128.representation(published[i].point),
                        proof: eqproof.eqProofToJSON(eqproof.proveEq(
                            published[0].point, published[i].point,
                            published[0].randomness, published[i].randomness, ctx)),
                    });
                }
                const tBidProve = now() - tBid0;
                cpProve = +(now() - tTotal).toFixed(1);

                // 6. Decision.
                // Two paths: (a) the deterministic decide() over decrypted plaintext, used
                // by the benchmark and the deviation experiments; or (b) a model-selected
                // merchant index (the LLM is the decision maker and saw the plaintext
                // prices). The feasibility split stays local; only the chosen index is the
                // model's. See src/llm/decision.js.
                let decision = agent.decide();
                if (Number.isInteger(body.selectedMerchant)) {
                    decision = decisionFromSelection(
                        body.selectedMerchant, agent.quotes, agent.limit && agent.limit.valueInt);
                    warnings.push(`Decision driven by model: selected merchant ${body.selectedMerchant}`);
                }

                // Deviation: select a feasible but non-cheapest offer. The optimality
                // proofs are built against this choice, so they cannot verify.
                if (cheat === 'biased-selection') {
                    const feasible = [];
                    for (let i = 0; i < agent.quotes.length; i++) {
                        if (agent.quotes[i] && agent.quotes[i].valueInt <= agent.limit.valueInt) feasible.push(i);
                    }
                    if (feasible.length > 1) {
                        const minId = feasible.reduce(
                            (b, i) => (agent.quotes[i].valueInt < agent.quotes[b].valueInt ? i : b), feasible[0]);
                        const alt = feasible.find((i) => i !== minId);
                        decision.chosen = alt;
                        warnings.push(`Deviation: selected merchant ${alt} instead of ${minId}`);
                    }
                }

                // 7. Build ZK proofs (C backend, single mode).
                // A deviating agent may ask for a proof it cannot construct (e.g. an
                // optimality proof for a non-cheapest choice opens a negative difference).
                // It then has no valid evidence to submit, so the purchase is rejected
                // here with a structured result rather than reaching the verifier.
                let bpResult;
                try {
                    // A model-made decision is the agent's own choice; when that choice
                    // cannot be proved (an over-limit or non-cheapest merchant), the
                    // agent must not police itself. It submits a decoy proof and lets the
                    // verifier and the provider reject it.
                    bpResult = buildDiffProofsC(agent, decision, N,
                        { forge: Number.isInteger(body.selectedMerchant) });
                } catch (e) {
                    const verification = {
                        allPass: false,
                        zkpVerified: false,
                        checks: [{ step: 'zkp.optimality', pass: false,
                            reason: `agent cannot construct the required proof: ${e.message}` }],
                    };
                    const rejection = {
                        public: {
                            verification,
                            commitments: { sellers: [], limit: sealedConstraint.commitment },
                            chosen: decision.chosen,
                            removed: decision.removed,
                            proofs: null,
                            registeredMerchants,
                            bidConsistency: { entries: bidEntries },
                            proofSizeBytes: null,
                            proofSizeBytesTotal: null,
                            cheat,
                            timingMs: {
                                total: +(now() - tTotal).toFixed(1),
                                bidProve: +tBidProve.toFixed(2),
                            },
                        },
                        agentView: {
                            quotesPlain: agent.quotes.map((q) => (q ? q.valueInt : null)),
                            limitPlain: agent.limit ? agent.limit.valueInt : null,
                            decision,
                        },
                        openCheckout: openCheckoutPresentation,
                        openPayment: openPaymentPresentation,
                        openCheckoutClaims: openCheckout.claims,
                        openPaymentClaims: openPayment.claims,
                        closedCheckout: null,
                        closedPayment: null,
                        checkoutReceipt: null,
                        paymentReceipt: null,
                        checks: { verifier: verification, cp: null, mpp: null },
                        credential: null,
                        warnings,
                        config: { n: N },
                    };
                    session.result = rejection;
                    return sendJSON(res, 200, { result: rejection });
                }
                const proveBreakdown = bpResult.timingMs;
                // Merchant price-validity proof generation time: max = per-merchant wall-clock
                // (merchants are independent parallel parties). Sum is reported separately so the
                // benchmark can subtract the single-process serialization artifact (sum - max).
                const tPriceProofSum = validMerchantResponses.reduce((sum, mr) => sum + (mr.tPriceProofMs || 0), 0);
                const tPriceProofGen = validMerchantResponses.length
                    ? Math.max(...validMerchantResponses.map((mr) => mr.tPriceProofMs || 0))
                    : 0;
                const tPriceProofMin = validMerchantResponses.length
                    ? Math.max(...validMerchantResponses.map((mr) => mr.tPriceProofMin || 0))
                    : 0;
                const tPriceProofMax = validMerchantResponses.length
                    ? Math.max(...validMerchantResponses.map((mr) => mr.tPriceProofMax || 0))
                    : 0;
                // Merchant-side commitment/encryption (C commit + ECIES): max = parallel
                // wall clock, sum = serialized.
                const tCommitSum = validMerchantResponses.reduce((sum, mr) => sum + (mr.tCommitMs || 0), 0);
                const tCommitGen = validMerchantResponses.length
                    ? Math.max(...validMerchantResponses.map((mr) => mr.tCommitMs || 0)) : 0;
                const tEncryptSum = validMerchantResponses.reduce((sum, mr) => sum + (mr.tEncryptMs || 0), 0);
                const tEncryptGen = validMerchantResponses.length
                    ? Math.max(...validMerchantResponses.map((mr) => mr.tEncryptMs || 0)) : 0;

                // 8. Serialize proofs.
                let proofs, proofSizeBytes, totalBytes;
                if (ZKP_MODE === 'single') {
                    const { infeasibleProofs, feasibleProofs, optimalityProofs } = bpResult;
                    // C backend: every proof is already a hex string (610 B); assemble directly.
                    proofs = {
                        priceValidity: {
                            min: Object.fromEntries(validMerchantResponses.map((mr) => [mr.id, mr.priceProof.min])),
                            max: Object.fromEntries(validMerchantResponses.map((mr) => [mr.id, mr.priceProof.max])),
                        },
                        infeasible: infeasibleProofs,
                        feasible: feasibleProofs,
                        optimality: optimalityProofs,
                    };
                    const countBytes = (m) => Object.fromEntries(Object.entries(m).map(([k, v]) => [k, v.length / 2 - 1]));
                    proofSizeBytes = {
                        priceValidity: {
                            min: countBytes(proofs.priceValidity.min),
                            max: countBytes(proofs.priceValidity.max),
                        },
                        infeasible: countBytes(infeasibleProofs),
                        feasible: countBytes(feasibleProofs),
                        optimality: countBytes(optimalityProofs),
                    };
                    totalBytes = ['priceValidity', 'infeasible', 'feasible', 'optimality'].reduce((sum, category) => {
                        const o = proofSizeBytes[category];
                        const entries = category === 'priceValidity'
                            ? [...Object.values(o.min), ...Object.values(o.max)]
                            : Object.values(o);
                        return sum + entries.reduce((a, b) => a + b, 0);
                    }, 0);
                } else {
                    throw new Error('C backend: aggregated mode not wired');
                }

                const publicData = {
                    agentPubkey: pointToHex(agent.pk),
                    commitments: {
                        sellers: validMerchantResponses.map((mr) => ({ i: mr.id, point: mr.commitment })),
                        limit: sealedConstraint.commitment,
                    },
                    chosen: decision.chosen,
                    // The selected offer is checked directly: send its opening so the
                    // provider can confirm the commitment matches the disclosed price.
                    chosenOpening: decision.chosen !== null && agent.quotes[decision.chosen]
                        ? {
                            value: agent.quotes[decision.chosen].valueInt,
                            blinding: agent.quotes[decision.chosen].blindingHex,
                        }
                        : null,
                    removed: decision.removed,
                    proofs,
                    proofCounts: {
                        infeasible: Object.keys(proofs.infeasible).length,
                        feasible: Object.keys(proofs.feasible).length,
                        optimality: Object.keys(proofs.optimality).length,
                    },
                    // AP2-E checks beyond the range proofs: the registered merchant set
                    // (response accounting) and the bid-consistency evidence.
                    registeredMerchants,
                    bidConsistency: { entries: bidEntries },
                    cheat,
                };

                // Deviation: drop the cheapest offer from the comparison evidence, as an
                // agent that never compared it would. Response accounting must catch it.
                if (cheat === 'offer-exclusion' && publicData.commitments.sellers.length > 1) {
                    let cheapestId = null;
                    let best = Infinity;
                    for (const seller of publicData.commitments.sellers) {
                        const q = agent.quotes[seller.i];
                        if (q && q.valueInt < best) { best = q.valueInt; cheapestId = seller.i; }
                    }
                    publicData.commitments.sellers = publicData.commitments.sellers.filter((s) => s.i !== cheapestId);
                    warnings.push(`Deviation: offer of merchant ${cheapestId} omitted`);
                }

                // 9. Build the closed mandates (SD-JWT handles, signed by the agent key).
                //    The verifier checks them together with the ZK evidence.
                let chosenResp = null;
                let closedCheckoutHandle = null;
                let closedPaymentHandle = null;
                const tClosed0 = now();
                if (decision.chosen !== null) {
                    chosenResp = validMerchantResponses.find((mr) => mr.id === decision.chosen);
                    closedCheckoutHandle = mandate.buildClosedCheckoutMandate({
                        agentPubkey: s.agentKp.pk,
                        agentSk: s.agentKp.sk,
                        checkoutJwt: chosenResp.checkoutJwt,
                        openCheckout: openCheckoutPresentation,
                    });
                    closedPaymentHandle = mandate.buildClosedPaymentMandateCommitted({
                        agentPubkey: s.agentKp.pk,
                        agentSk: s.agentKp.sk,
                        checkoutJwt: chosenResp.checkoutJwt,
                        payee: chosenResp.merchant,
                        amountCommitment: chosenResp.commitment,
                        currency: sealedConstraint.currency || 'USD',
                        paymentInstrument: { id: 'pi_demo', type: 'card', description: 'demo instrument' },
                        openPayment: openPaymentPresentation,
                        evidence: proofs,
                    });
                }
                const closedCheckoutPresentation = closedCheckoutHandle ? closedCheckoutHandle.present() : null;
                const closedPaymentPresentation = closedPaymentHandle ? closedPaymentHandle.present() : null;
                const tBuildClosed = now() - tClosed0;

                // 9b. The merchant verifies the user's checkout mandates before the
                // purchase proceeds, as in AP2: it sees the open mandate bound to the
                // signed checkout and returns a receipt.
                let tMerchantVerify = 0;
                if (decision.chosen !== null && chosenResp && closedCheckoutPresentation) {
                    const tMv0 = now();
                    try {
                        const merchantKb = await attachKeyBinding(
                            closedCheckoutPresentation, AUD.merchant, warnings);
                        const mvResp = await fetch(`${merchantUrl}/verify-checkout`, {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                openCheckoutPresentation,
                                closedCheckoutPresentation,
                                checkoutJwt: chosenResp.checkoutJwt,
                                userPubkey: anchor,
                                ...(merchantKb ? { kb: merchantKb } : {}),
                            }),
                        });
                        const mvData = await mvResp.json().catch(() => ({}));
                        if (!(mvResp.ok && mvData.checks && mvData.checks.ok)) {
                            warnings.push('Merchant rejected the checkout mandates');
                        }
                    } catch (e) {
                        warnings.push(`Merchant checkout verification unreachable: ${e.message}`);
                    }
                    tMerchantVerify = now() - tMv0;
                }

                // 10. Independent Verifier: mandate-bound verification.
                //     The verifier checks: user SD-JWT -> agent SD-JWT -> bindings -> ZKP.
                //     A single-use nonce binds both closed presentations (kb-sd-jwt).
                const tVerify = now();
                let verification;
                try {
                    const kb = await verifierKeyBindings({
                        closedCheckoutPresentation,
                        closedPaymentPresentation,
                        holderSk: s.agentKp.sk,
                        warnings,
                    });
                    const vResp = await fetch(`${verifierUrl}/verify-mandate`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            openCheckoutPresentation,
                            openPaymentPresentation,
                            closedCheckoutPresentation,
                            closedPaymentPresentation,
                            checkoutJwt: chosenResp ? chosenResp.checkoutJwt : null,
                            merchantCheckoutHash: chosenResp ? chosenResp.checkoutHash : null,
                            merchantId: decision.chosen,
                            publicData,
                            n: N,
                            userPubkey: anchor,
                            qid,
                            registeredMerchants,
                            bidConsistency: { entries: bidEntries },
                            ...(kb ? { kb } : {}),
                        }),
                    });
                    if (vResp.ok) {
                        verification = await vResp.json();
                    } else {
                        throw new Error('Verifier returned non-OK');
                    }
                } catch (e) {
                    warnings.push(`Verifier unreachable: ${e.message}`);
                    verification = { allPass: false, checks: [{ step: 'error', pass: false, reason: e.message }] };
                }
                const tVerifyMs = now() - tVerify;
                cpVerify = +(now() - tTotal).toFixed(1);
                const vTiming = (verification.zkpResult && verification.zkpResult.timingMs) || {};

                // 11. Credential provider verifies the Payment Mandates and issues a token,
                //     then the MPP settles and returns the Payment Receipt.
                let credential = null;
                let paymentReceipt = null;
                let mppChecks = null;
                let cpChecks = null;
                let tCp = 0;
                let tMpp = 0;
                try {
                    if (verification.allPass && closedPaymentPresentation) {
                        const tCp0 = now();
                        const cpKb = await attachKeyBinding(closedPaymentPresentation, AUD.cp, warnings);
                        const provResp = await fetch(`${providerUrl}/issue`, {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                openPaymentPresentation,
                                closedPaymentPresentation,
                                openCheckoutPresentation,
                                userPubkey: anchor,
                                zkpVerified: verification.zkpVerified === true,
                                ...(cpKb ? { kb: cpKb } : {}),
                            }),
                        });
                        const provData = await provResp.json();
                        tCp = now() - tCp0;
                    cpIssue = +(now() - tTotal).toFixed(1);
                        cpChecks = provData.checks || null;
                        if (provResp.ok) {
                            credential = provData.token;
                            const tMpp0 = now();
                            const mppKb = await attachKeyBinding(closedPaymentPresentation, AUD.mpp, warnings);
                            const mppResp = await fetch(`${mppUrl}/process`, {
                                method: 'POST', headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    token: credential,
                                    tokenJwt: provData.tokenJwt,
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
                            paymentReceipt = provData.receipt || null;
                            warnings.push('Credential Provider rejected the Payment Mandate');
                        }
                    } else if (!verification.allPass) {
                        warnings.push('Independent verifier rejected the purchase evidence');
                    }
                } catch (e) {
                    warnings.push(`Provider/MPP unreachable: ${e.message}`);
                }

                const tTotalMs = now() - tTotal;

                const result = {
                    public: {
                        ...publicData,
                        verification,
                        proofSizeBytes,
                        proofSizeBytesTotal: totalBytes,
                        timingMs: {
                            priceProofGen: +tPriceProofGen.toFixed(1),
                            priceProofSum: +tPriceProofSum.toFixed(1),
                            merchantCommitGen: +tCommitGen.toFixed(1),
                            merchantCommitSum: +tCommitSum.toFixed(1),
                            merchantEncryptGen: +tEncryptGen.toFixed(1),
                            merchantEncryptSum: +tEncryptSum.toFixed(1),
                            ...(ZKP_MODE === 'single'
                                ? {
                                    priceProofMin: +tPriceProofMin.toFixed(1),
                                    priceProofMax: +tPriceProofMax.toFixed(1),
                                    proveInfeasible: proveBreakdown.infeasible || 0,
                                    proveFeasible: proveBreakdown.feasible || 0,
                                    proveOptimality: proveBreakdown.optimality || 0,
                                }
                                : {}),
                            prove: proveBreakdown.prove,
                            bidProve: +tBidProve.toFixed(2),
                            quotes: +tQuotes.toFixed(1),
                            checkoutGenMax: +tCheckoutGenMax.toFixed(2),
                            quoteFetchMax: quoteDurations.length ? +Math.max(...quoteDurations).toFixed(2) : 0,
                            quotePrep: tQuotePrep,
                            quoteBlock: quoteDurations.length ? +Math.max(...quoteDurations).toFixed(2) : 0,
                            quoteFetchSum: +quoteDurations.reduce((a, v) => a + v, 0).toFixed(2),
                            quoteDurations: quoteDurations.map((v) => +v.toFixed(1)),
                            handlerDurations: merchantResponses.map((r) => +(r.tHandlerMs || 0).toFixed(1)),
                            merchantTimeline: merchantResponses.map((r) => ({
                                id: r.id,
                                recv: r.tRecvMs,
                                start: r.tHandlerStartMs,
                                end: r.tEndMs,
                                handler: r.tHandlerMs,
                            })),
                            handlerMax: merchantResponses.length
                                ? +Math.max(...merchantResponses.map((r) => r.tHandlerMs || 0)).toFixed(2) : 0,
                            handlerSum: +merchantResponses.reduce((a, r) => a + (r.tHandlerMs || 0), 0).toFixed(2),
                            checkoutGenSum: +tCheckoutGenSum.toFixed(2),
                            merchantSubmitMax: +tSubmitMax.toFixed(2),
                            merchantSubmitSum: +tSubmitSum.toFixed(2),
                            buildClosed: +tBuildClosed.toFixed(1),
                            merchantVerify: +tMerchantVerify.toFixed(1),
                            cp: +tCp.toFixed(1),
                            mpp: +tMpp.toFixed(1),
                            verify: +tVerifyMs.toFixed(1),
                            // What the verifier itself spent, broken down (bid consistency and
                            // response accounting are part of the prototype's verification).
                            verifierBidVerify: (verification.timingMs && verification.timingMs.bidVerify) || 0,
                            verifierBidAck: (verification.timingMs && verification.timingMs.bidAck) || 0,
                            verifierAccounting: (verification.timingMs && verification.timingMs.accounting) || 0,
                            verifyPriceValidityCollection: priceValidityCollectionMs,
                            verifierMandates: (verification.timingMs && verification.timingMs.mandates) || 0,
                            verifyPriceValidity: vTiming.priceValidity || 0,
                            ...(ZKP_MODE === 'single'
                                ? {
                                    verifyPriceValidityMin: vTiming.priceValidityMin || 0,
                                    verifyPriceValidityMax: vTiming.priceValidityMax || 0,
                                    verifyInfeasible: vTiming.infeasible || 0,
                                    verifyFeasible: vTiming.feasible || 0,
                                    verifyOptimality: vTiming.optimality || 0,
                                }
                                : { verifyAgent: vTiming.agent || 0 }),
                            total: +tTotalMs.toFixed(1),
                            checkpoints: { quotes: cpQuotes, prove: cpProve, verify: cpVerify, issue: cpIssue },
                            fixWait: +fixWaitMs.toFixed(1),
                        },
                    },
                    agentView: {
                        quotesPlain: agent.quotes.map((q) => (q ? q.valueInt : null)),
                        limitPlain: agent.limit ? agent.limit.valueInt : null,
                        decision,
                    },
                    // Wire artefacts: presentations only, never the handles.
                    openCheckout: openCheckoutPresentation,
                    openPayment: openPaymentPresentation,
                    closedCheckout: closedCheckoutPresentation,
                    closedPayment: closedPaymentPresentation,
                    // Recovered/issued claims, for local inspection (never forwarded whole).
                    openCheckoutClaims: openCheckout.claims,
                    openPaymentClaims: openPayment.claims,
                    closedCheckoutClaims: closedCheckoutHandle ? closedCheckoutHandle.claims : null,
                    closedPaymentClaims: closedPaymentHandle ? closedPaymentHandle.claims : null,
                    checkoutReceipt: null,
                    paymentReceipt,
                    checks: { verifier: verification, cp: cpChecks, mpp: mppChecks },
                    credential,
                    warnings,
                    config: { n: N },
                };
                session.result = result;
                return sendJSON(res, 200, { result });
            } catch (e) {
                return sendJSON(res, 400, { error: e.message, warnings });
            }
        }

        // ---- GET /result ----
        if (req.method === 'GET' && pathname === '/result') {
            if (!session || !session.result) return sendJSON(res, 404, { error: 'No result.' });
            return sendJSON(res, 200, { result: session.result });
        }

        // ---- POST /reset ----
        if (req.method === 'POST' && pathname === '/reset') { session = null; return sendJSON(res, 200, { ok: true }); }

        // ---- GET /api/meta 鈥?size/timing accounting for the comparison dashboard ----
        if (req.method === 'GET' && pathname === '/api/meta') {
            if (!session || !session.result) return sendJSON(res, 404, { error: 'No result.' });
            const r = session.result;
            const pub = r.public || {};
            const timing = pub.timingMs || {};
            // The mandates on the wire are presentation strings; their JWS signatures are
            // part of those bytes, so total = proof bytes + mandate bytes.
            const presentations = [r.openCheckout, r.openPayment, r.closedCheckout, r.closedPayment]
                .filter((p) => typeof p === 'string' && p.length > 0);
            const mandateBytes = presentations.reduce((a, p) => a + p.length, 0);
            const signatureBytes = presentations.reduce((a, p) => {
                const parts = p.split('.');
                return a + (parts.length === 3 ? Math.floor(parts[2].length * 3 / 4) : 0);
            }, 0);
            const proofBytes = pub.proofSizeBytesTotal || 0;
            return sendJSON(res, 200, {
                system: { id: 3, name: 'Full (AP2+ZKP)' },
                sizes: { proofBytes, signatureBytes, mandateBytes, total: proofBytes + mandateBytes },
                timings: { proveMs: timing.prove, verifyMs: timing.verify, totalMs: timing.total },
                verification: !!(pub.verification && pub.verification.allPass),
                revealed: [],
            });
        }

        if (req.method === 'GET' && pathname === '/health') {
            return sendJSON(res, 200, { ok: true, merchantUrl, verifierUrl, providerUrl, mppUrl });
        }

        if (req.method === 'GET') return serveStatic(WEB_ROOT, decodeURIComponent(pathname), res);

        sendJSON(res, 405, { error: 'Method Not Allowed' });
    };
}

function start(opts) {
    const port = opts.port || 3301;
    const merchantUrl = opts.merchantUrl || 'http://localhost:3310';
    const verifierUrl = opts.verifierUrl || 'http://localhost:3390';
    const providerUrl = opts.providerUrl || 'http://localhost:3290';
    const mppUrl = opts.mppUrl || 'http://localhost:3395';
    const server = http.createServer(createHandler({ merchantUrl, verifierUrl, providerUrl, mppUrl }));
    return new Promise((resolve, reject) => {
        server.on('error', reject);
        server.listen(port, () => {
            console.log(`鉁?Full Agent Server: http://localhost:${port}`);
            console.log(`  Merchant: ${merchantUrl}   Verifier: ${verifierUrl}   Provider: ${providerUrl}`);
            resolve(server);
        });
    });
}

if (require.main === module) {
    const { getArg } = require('../common/http-utils');
    const port = parseInt(getArg(process.argv, '--port', '3301'), 10);
    const merchantUrl = getArg(process.argv, '--merchant-url', 'http://localhost:3310');
    const verifierUrl = getArg(process.argv, '--verifier-url', 'http://localhost:3390');
    const providerUrl = getArg(process.argv, '--provider-url', 'http://localhost:3290');
    const mppUrl = getArg(process.argv, '--mpp-url', 'http://localhost:3395');
    start({ port, merchantUrl, verifierUrl, providerUrl, mppUrl });
}

module.exports = { start };
