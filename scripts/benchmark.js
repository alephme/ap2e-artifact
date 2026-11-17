// Statistical benchmark: multiple random scenarios per (nMerchants, n) combination.
// Outputs results.json for paper analysis.
//
// Usage:
//   node scripts/benchmark.js                    # default: 10 groups, all combinations
//   node scripts/benchmark.js --groups 5         # 5 groups per combination
//   node scripts/benchmark.js --merchants 4,8    # only 4- and 8-merchant
//   node scripts/benchmark.js --nbits 16         # only n=16
//   node scripts/benchmark.js --output mydata.json
//   node scripts/benchmark.js --port-offset 1000  # avoid port conflicts when running two instances
//   node scripts/benchmark.js --seed 42           # deterministic scenarios (reproducible runs)

const fs = require('fs');
const { spawn } = require('child_process');
const c = require('../src/crypto/c-backend');
const { start: startMerchant } = require('../src/systems/merchant-server');
const { start: startVerifier } = require('../src/systems/verifier-server');
const { start: startProvider } = require('../src/systems/credential-provider');
const { start: startMpp } = require('../src/systems/mpp-server');
const { start: startAp2Agent } = require('../src/systems/ap2-only/agent-server');
const { start: startFullAgent } = require('../src/systems/full/agent-server');
const keys = require('../src/mandates/keys');
const mandate = require('../src/mandates/mandate');
const { randomCommit, pointToHex, openingToJson, hexToPoint } = require('../src/shopping/commitments');
const ecies = require('../src/crypto/ecies');
const eqproof = require('../src/crypto/eqproof');

// ---- Config ----
function getArg(name, dflt) {
    const idx = process.argv.indexOf(name);
    return idx >= 0 ? process.argv[idx + 1] : dflt;
}

const GROUPS = parseInt(getArg('--groups', '10'), 10);
const MERCHANT_SIZES = (getArg('--merchants', '4,8') || '4,8').split(',').map(Number);
const NBITS = (getArg('--nbits', '16,32') || '16,32').split(',').map(Number);
const OUTPUT = getArg('--output', 'benchmark-results.json');
const PORT_OFFSET = parseInt(getArg('--port-offset', '0'), 10);
const ZKP_MODE = process.env.ZKP_MODE || 'single'; // 'aggregated' | 'single'（C 后端仅 single）

// --seed makes scenario generation deterministic (reproducible across machines/runs).
// Only scenario inputs (quotes/limit) are seeded; cryptographic randomness (commitments,
// ECIES) intentionally stays on the CSPRNG.
const SEED_RAW = getArg('--seed', '');
const SEED = SEED_RAW === '' ? null : (parseInt(SEED_RAW, 10) || 0);
function mulberry32(a) {
    return function () {
        a |= 0; a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
const rand = SEED == null ? () => Math.random() : mulberry32(SEED);

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- Generate random scenarios ----
function randInt(min, max) {
    return Math.floor(rand() * (max - min + 1)) + min;
}

function generateScenarios(nMerchants, nGroups) {
    // Generate nGroups random (quotes, limit) pairs.
    // Limit is chosen so the #removed is roughly between 1/3 and 2/3 of merchants.
    const scenarios = [];
    for (let g = 0; g < nGroups; g++) {
        const quotes = Array.from({ length: nMerchants }, () => randInt(10, 500));
        const sorted = [...quotes].sort((a, b) => a - b);
        // Pick limit at a random percentile between 30% and 70%
        const pctIdx = randInt(Math.floor(nMerchants * 0.3), Math.floor(nMerchants * 0.7));
        const limit = sorted[pctIdx] + randInt(-5, 5); // small jitter
        scenarios.push({
            id: `M${nMerchants}_g${g}`,
            quotes,
            limit: Math.max(limit, sorted[0] - 1), // ensure at least 1 below limit
        });
    }
    return scenarios;
}

// Bytes of the JWS signature segment inside an SD-JWT presentation (jwt~disc~...).
function jwsSignatureBytes(presentation) {
    if (typeof presentation !== 'string') return 0;
    const jwt = presentation.split('~')[0];
    const parts = jwt.split('.');
    return parts.length === 3 ? parts[2].length : 0;
}

// ---- Benchmark one scenario ----
async function benchmarkOne(scenario, n, userKp) {
    const { quotes, limit } = scenario;
    const tSetup = performance.now(); //单次quote开始时间

    // The enrolled user key and the servers are created once in main(): the parties
    // are long-lived processes, as they would be in a deployment.


    const record = { scenario: scenario.id, nMerchants: quotes.length, n, limit, quotes, systems: {} };
    const allowed = quotes.map((_, i) => mandate.merchant({
        id: i, name: `Merchant ${i}`, website: `https://merchant${i}.example`,
    }));

    try {
        // Two passes: the first pays connection setup and handler JIT (measured at
        // ~80 ms at m=4 on freshly started servers) and is discarded; the second is
        // recorded. Without this the AP2 row is inflated several-fold.
        for (let pass = 0; pass < 2; pass++) {
        // ===== AP2-Only =====
        {
            const tStart = performance.now();
            const buildResp = await fetch(`http://localhost:${P.ap2A}/build-mandate`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userPubkey: userKp.pk, userSk: userKp.sk,
                    currency: 'USD', maxAmount: limit, allowedMerchants: allowed,
                }),
            });
            const buildData = await buildResp.json();
            if (buildData.error) throw new Error('AP2 build: ' + buildData.error);
            const tBuild = performance.now() - tStart;

            // The user signs the open mandates inside /build-mandate (SD-JWT is signed at
            // issuance), so there is no separate user-signature step any more.
            const tSign = 0;

            const execResp = await fetch(`http://localhost:${P.ap2A}/execute`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    openCheckoutPresentation: buildData.openCheckoutPresentation,
                    openPaymentPresentation: buildData.openPaymentPresentation,
                    userPubkey: userKp.pk,
                }),
            });
            const execData = await execResp.json();
            const tExecRaw = performance.now() - tStart;
            if (execData.error) throw new Error('AP2 exec: ' + execData.error);

            const r = execData.result;
            const tm = r.timingMs || {};
            // Merchants are independent parallel parties: the merchant-side work is max
            // (one merchant), not sum. Subtracting (sum - max) removes the single-process
            // serialisation artifact. We use the FULL checkout generation when the agent
            // reports it (payload + JWS + hash), because the ECDSA part alone is only a
            // third of the per-merchant cost; otherwise fall back to the signature.
            const genArtifact = Math.max(0, (tm.checkoutGenSum || 0) - (tm.checkoutGenMax || 0));
            const signArtifact = Math.max(0, (tm.checkoutSignSum || 0) - (tm.checkoutSignMax || 0));
            const merchantSerialArtifact = genArtifact > 0 ? genArtifact : signArtifact;
            const tExec = +(tExecRaw - merchantSerialArtifact).toFixed(2);

            const sigBytes = [r.openCheckout, r.openPayment, r.closedCheckout, r.closedPayment]
                .reduce((a, p) => a + jwsSignatureBytes(p), 0);
            const mandateBytes = [r.openCheckout, r.openPayment, r.closedCheckout, r.closedPayment]
                .reduce((a, p) => a + (typeof p === 'string' ? Buffer.byteLength(p) : 0), 0) - sigBytes;
            const ap2Authorized = !!(r.checks && r.checks.merchant && r.checks.merchant.ok
                && r.checks.cp && r.checks.cp.ok && r.checks.mpp && r.checks.mpp.ok);
            const nRemoved = quotes.filter((q) => q >= limit).length;

            record.systems.ap2Only = {
                tBuild: +tBuild.toFixed(2),
                tSign: +tSign.toFixed(2),
                tTotal: tExec,
                tTotalRaw: +tExecRaw.toFixed(2),
                merchantSerialArtifact: +merchantSerialArtifact.toFixed(2),
                // per-phase costs, mirroring the AP2-E rows
                tMerchantSignMax: tm.checkoutSignMax || 0,   // per merchant, parallel
                tMerchantGenMax: tm.checkoutGenMax || 0,     // payload + JWS + hash, parallel
                tQuotes: tm.quotes || 0,                     // agent fetch round
                // Fetch wall clock with the merchant-serialisation artifact removed, i.e.
                // what the parallel-merchant model implies.
                tQuotesCorrected: +Math.max(0, (tm.quotes || 0) - merchantSerialArtifact).toFixed(2),
                tBuildClosed: tm.buildClosed || 0,           // agent signs both closed mandates
                tMerchantVerify: tm.merchantVerify || 0,     // merchant verifies the checkout half
                tCp: tm.cp || 0,                             // CP verifies the payment half
                tMpp: tm.mpp || 0,                           // MPP settles
                tAgentVerifyMerchants: tm.verifyMerchants || 0, // optional, off by default
                sigBytes,
                mandateBytes,
                nSignatures: 4,
                nRemoved,
                chosen: r.chosenMerchantId,
                purchased: r.chosenMerchantId !== null,
                // A scenario with no feasible offer has nothing to authorise; it is not
                // a verification failure.
                pass: r.chosenMerchantId === null ? true : ap2Authorized,
            };
            await fetch(`http://localhost:${P.ap2A}/reset`, { method: 'POST' });
        }

        // ===== Full =====
        {
            const pkResp = await fetch(`http://localhost:${P.fullA}/pubkey`);
            const pkData = await pkResp.json();

            // Per-merchant cost measured in isolation: merchants are independent parties,
            // so the parallel wall clock is one merchant's cost. Measuring it inside the
            // m-way concurrent round would include event-loop queueing in the merchant
            // process and inflate it with m.
            const probe = await (await fetch(
                `http://localhost:${P.fullM}/quote/0?agentPubkey=${encodeURIComponent(pkData.eciesPubkey)}&n=${n}`,
            )).json();
            const tMerchantCommitIsolated = probe.tCommitMs || 0;
            const tMerchantEncryptIsolated = probe.tEncryptMs || 0;

            const t0 = performance.now();

            // 用户侧密码学拆分计时：承诺与加密分开（承诺走 C 后端）。
            const tCommit0 = performance.now();
            const blind = c.randomBlind();
            const cmt = c.commit(blind, limit);       // Pedersen 承诺（C，secp256k1）
            const tCommit = performance.now() - tCommit0;

            const tEncrypt0 = performance.now();
            // ECIES 加密（JS 通信层）：ECDH → SHA-256 → AES-256-GCM
            const sealed = await ecies.encrypt(hexToPoint(pkData.eciesPubkey),
                JSON.stringify({ value: String(limit), blinding: blind.toString('hex') }));
            const tEncrypt = performance.now() - tEncrypt0;

            const tUserCrypto = performance.now() - t0;   // 用户侧合计（含 fetch/密钥生成/承诺/加密）

            // Bid consistency and response accounting are produced and checked inside the
            // real protocol flow (agent builds the equality proofs, the verifier checks
            // them), so they are read from the run instead of being simulated here.

            // The timed region starts before the provider-side build of the open mandates,
            // so that both systems cover the same steps (AP2's timer already does).
            const t1 = performance.now();
            const buildResp = await fetch(`http://localhost:${P.fullA}/build-mandate`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userPubkey: userKp.pk,
                    userSk: userKp.sk,
                    currency: 'USD',
                    sealedMaxUnitPrice: { commitment: c.commitToHex(cmt), sealed },
                    allowedMerchants: allowed,
                }),
            });
            const buildData = await buildResp.json();
            if (buildData.error) throw new Error('Full build: ' + buildData.error);
            const tBuildFull = performance.now() - t1;

            // Signed by the user inside /build-mandate.
            const tSign = 0;

            const execResp = await fetch(`http://localhost:${P.fullA}/execute`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    openCheckoutPresentation: buildData.openCheckoutPresentation,
                    openPaymentPresentation: buildData.openPaymentPresentation,
                    userPubkey: userKp.pk,
                    n,
                }),
            });
            const execData = await execResp.json();
            const tExec = performance.now() - t1;
            if (execData.error) throw new Error('Full exec: ' + execData.error);

            const pub = execData.result.public;
            // Bid consistency, measured on the real path: the agent builds the equality
            // proofs and the verifier checks them.
            const bidEntries = (pub.bidConsistency && pub.bidConsistency.entries) || [];
            const tInquiryProve = pub.timingMs.bidProve || 0;
            const tInquiryVerify = pub.timingMs.verifierBidVerify || 0;
            const tAccounting = pub.timingMs.verifierAccounting || 0;
            const tBidAck = pub.timingMs.verifierBidAck || 0;
            const tVerifyPriceAtCollection =
                (pub.verification && pub.verification.timingMs
                    && pub.verification.timingMs.priceValidityAtCollection)
                || pub.timingMs.verifyPriceValidityCollection || 0;
            const tMerchantSubmit = pub.timingMs.merchantSubmitMax || 0;
            const inquiryProofBytes = bidEntries.length
                ? JSON.stringify(bidEntries).length
                : 0;
            const inquiryN = bidEntries.length;
            const inquiryOk = pub.verification ? pub.verification.allPass : false;
            const r = execData.result;
            const sigBytes = [r.openCheckout, r.openPayment, r.closedCheckout, r.closedPayment]
                .reduce((a, p) => a + jwsSignatureBytes(p), 0);
            // The closed Payment Mandate carries the ZK evidence inside its JWT payload.
            // Those bytes are counted as proof bytes, so remove them here (the payload is
            // base64url-encoded, hence the 4/3 factor).
            const evidenceBytes = (r.closedPaymentClaims && r.closedPaymentClaims.evidence)
                ? Math.ceil(JSON.stringify(r.closedPaymentClaims.evidence).length * 4 / 3) : 0;
            const mandateBytes = [r.openCheckout, r.openPayment, r.closedCheckout, r.closedPayment]
                .reduce((a, p) => a + (typeof p === 'string' ? Buffer.byteLength(p) : 0), 0)
                - sigBytes - evidenceBytes;

            // Proof counts: aggregated = |S| price-validity + 1 agent; single = 2|S| price-validity
            // + |S| classification + (x−1) optimality. Decision counts reflect the scenario.
            const nInf = pub.removed.length;                       // infeasible diffs
            const nFeas = quotes.length - pub.removed.length;      // feasible diffs
            const nOpt = pub.chosen !== null ? nFeas - 1 : 0;      // optimality diffs
            const single = ZKP_MODE === 'single';
            const nPrice = single
                ? Object.keys(pub.proofs?.priceValidity?.min || {}).length * 2
                : Object.keys(pub.proofs?.priceValidity || {}).length;
            const nProofs = single
                ? nPrice + nInf + nFeas + nOpt
                : nPrice + (pub.proofs?.agent ? 1 : 0);

            // tTotal reflects protocol semantics: merchants are independent parallel parties, so the
            // merchant proof-generation phase costs max (wall-clock of the slowest merchant), not the
            // sum incurred by the single merchant-server process handling all requests serially.
            // Subtract the serialization artifact: sum - max.
            const tPriceProofGen = pub.timingMs.priceProofGen || 0;   // max (parallel wall-clock)
            const tPriceProofSum = pub.timingMs.priceProofSum || 0;   // sum (single-process serial)
            const tTotalCorrected = +(tUserCrypto + tSign + tExec - (tPriceProofSum - tPriceProofGen)).toFixed(2);

            record.systems.full = {
                tUserCrypto: +tUserCrypto.toFixed(2),
                tBuildFull: +tBuildFull.toFixed(2),
                tInquiryProve: +tInquiryProve.toFixed(2),
                tInquiryVerify: +tInquiryVerify.toFixed(2),
                tAccounting: +tAccounting.toFixed(2),
                tBidAck: +tBidAck.toFixed(2),
                tVerifyPriceAtCollection: +tVerifyPriceAtCollection.toFixed(2),
                cpQuotes: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.quotes) || 0,
                cpProve: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.prove) || 0,
                cpVerify: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.verify) || 0,
                cpIssue: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.issue) || 0,
                cpQuotes: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.quotes) || 0,
                cpProve: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.prove) || 0,
                cpVerify: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.verify) || 0,
                cpIssue: (pub.timingMs.checkpoints && pub.timingMs.checkpoints.issue) || 0,
                fixWait: pub.timingMs.fixWait || 0,
                tCheckoutGenMax: pub.timingMs.checkoutGenMax || 0,
                tCheckoutGenSum: pub.timingMs.checkoutGenSum || 0,
                quoteFetchMax: pub.timingMs.quoteFetchMax || 0,
                quoteFetchSum: pub.timingMs.quoteFetchSum || 0,
                tMerchantSubmit: +tMerchantSubmit.toFixed(2),
                inquiryProofBytes,
                inquiryN,
                inquiryOk,
                tCommit: +tCommit.toFixed(2),
                tEncrypt: +tEncrypt.toFixed(2),
                tSign: +tSign.toFixed(2),
                tPriceProofGen,
                tPriceProofSum,
                tMerchantCommit: tMerchantCommitIsolated,    // 商家承诺（并行 max）
                tMerchantCommitSum: pub.timingMs.merchantCommitSum || 0, // 商家承诺（串行 sum）
                tMerchantEncrypt: tMerchantEncryptIsolated,  // 商家 ECIES 加密（并行 max）
                tMerchantEncryptSum: pub.timingMs.merchantEncryptSum || 0,
                ...(single
                    ? {
                        tPriceProofMin: pub.timingMs.priceProofMin || 0,
                        tPriceProofMax: pub.timingMs.priceProofMax || 0,
                        tProveInfeasible: pub.timingMs.proveInfeasible || 0,
                        tProveFeasible: pub.timingMs.proveFeasible || 0,
                        tProveOptimality: pub.timingMs.proveOptimality || 0,
                    }
                    : {}),
                tProve: pub.timingMs.prove,
                tQuotesFull: pub.timingMs.quotes || 0,
                tCpFull: pub.timingMs.cp || 0,
                tMppFull: pub.timingMs.mpp || 0,
                tBuildClosedFull: pub.timingMs.buildClosed || 0,
                tMerchantVerifyFull: pub.timingMs.merchantVerify || 0,
                tHandlerMax: pub.timingMs.handlerMax || 0,
                tCheckoutGenFull: pub.timingMs.checkoutGenMax || 0,
                tQuoteFetchMax: pub.timingMs.quoteFetchMax || 0,
                tQuotePrep: pub.timingMs.quotePrep || 0,
                tQuoteBlock: pub.timingMs.quoteBlock || 0,
                tFixWait: pub.timingMs.fixWait || 0,
                quoteDurations: pub.timingMs.quoteDurations || [],
                handlerDurations: pub.timingMs.handlerDurations || [],
                merchantTimeline: pub.timingMs.merchantTimeline || [],
                tVerify: pub.timingMs.verify,
                tVerifyPriceValidity: pub.timingMs.verifyPriceValidity || 0,
                ...(single
                    ? {
                        tVerifyPriceValidityMin: pub.timingMs.verifyPriceValidityMin || 0,
                        tVerifyPriceValidityMax: pub.timingMs.verifyPriceValidityMax || 0,
                        tVerifyInfeasible: pub.timingMs.verifyInfeasible || 0,
                        tVerifyFeasible: pub.timingMs.verifyFeasible || 0,
                        tVerifyOptimality: pub.timingMs.verifyOptimality || 0,
                    }
                    : { tVerifyAgent: pub.timingMs.verifyAgent || 0 }),
                tTotal: tTotalCorrected,
                tTotalSerialized: +(tUserCrypto + tSign + tExec).toFixed(2),
                proofBytes: pub.proofSizeBytesTotal,
                sigBytes,
                mandateBytes,
                nProofs,
                nPriceValidity: nPrice,
                ...(single ? {} : { nAgentProof: pub.proofs?.agent ? 1 : 0 }),
                nInfeasible: nInf,
                nFeasible: nFeas,
                nOptimality: nOpt,
                // Counts of the arguments actually generated. The selected offer carries
                // no Classify argument, so the affordable count is one lower than the
                // number of feasible offers.
                nInfeasibleProofs: Object.keys((pub.proofs && pub.proofs.infeasible) || {}).length,
                nFeasibleProofs: Object.keys((pub.proofs && pub.proofs.feasible) || {}).length,
                nOptimalityProofs: Object.keys((pub.proofs && pub.proofs.optimality) || {}).length,
                nRemoved: pub.removed.length,
                nSignatures: 4,
                chosen: pub.chosen,
                allPass: pub.verification.allPass,
                failedChecks: [
                    ...((pub.verification && pub.verification.checks) || []),
                    ...((pub.verification && pub.verification.zkpResult
                        && pub.verification.zkpResult.checks) || []),
                ].filter((c) => c && c.pass === false).map((c) => `${c.step}: ${c.reason || ''}`),
                warnings: (execData.result && execData.result.warnings) || [],
            };
            await fetch(`http://localhost:${P.fullA}/reset`, { method: 'POST' });
        }
        }
    } catch (e) {
        record.error = e.message;
    }

    // The servers stay up for the whole run.


    return record;
}

// ---- Statistics helpers ----
function avg(arr) {
    if (!arr.length) return null;
    const sum = arr.reduce((a, b) => a + b, 0);
    return +(sum / arr.length).toFixed(2);
}

function std(arr) {
    if (arr.length < 2) return null;
    const m = arr.reduce((a, b) => a + b, 0) / arr.length;
    return +Math.sqrt(arr.reduce((a, b) => a + (b - m) ** 2, 0) / (arr.length - 1)).toFixed(2);
}

// ---- Main ----
// ---- party processes ----
// Every party runs in its own OS process, so merchant work, provider verification and
// agent proving can occupy different cores, as they would across machines. The
// in-process helpers exported by the servers are still used by the fault-injection
// scripts, which need to tamper with the parties from inside.
const BASE_PORTS = {
    ap2M: 18210, ap2A: 18201,
    fullM: 18310, fullA: 18301, fullV: 18390,
    prov: 18490, mpp: 18395,
};
const P = Object.fromEntries(
    Object.entries(BASE_PORTS).map(([k, v]) => [k, v + PORT_OFFSET])
);

const CHILDREN = [];

function spawnServer(label, script, args) {
    const child = spawn(process.execPath, [script, ...args], { stdio: 'ignore' });
    child.on('exit', (code) => {
        if (code !== 0 && code !== null) console.error(`  ${label} exited with code ${code}`);
    });
    CHILDREN.push({ label, child });
    return child;
}

async function waitReady(label, port, timeoutMs = 30000) {
    const url = `http://localhost:${port}/health`;
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
        try {
            const r = await fetch(url);
            if (r.ok) return;
        } catch (e) { /* not listening yet */ }
        await sleep(40);
    }
    throw new Error(`${label} did not become ready on port ${port}`);
}

async function setQuotes(port, quotes) {
    const r = await fetch(`http://localhost:${port}/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ quotes }),
    });
    if (!r.ok) throw new Error(`quote update failed on port ${port}`);
}

function stopServers() {
    for (const { child } of CHILDREN) {
        try { child.kill('SIGTERM'); } catch (e) { /* already gone */ }
    }
}

async function startServers(userPubkey, quotes) {
    const q = quotes.join(',');
    const at = (p) => `http://localhost:${p}`;
    spawnServer('ap2-merchant', 'src/systems/merchant-server.js',
        ['--port', String(P.ap2M), '--mode', 'plain', '--quotes', q, '--user-pubkey', userPubkey]);
    spawnServer('verifier', 'src/systems/verifier-server.js',
        ['--port', String(P.fullV), '--user-pubkey', userPubkey]);
    spawnServer('ap2e-merchant', 'src/systems/merchant-server.js',
        ['--port', String(P.fullM), '--mode', 'sealed', '--quotes', q, '--user-pubkey', userPubkey,
            '--provider-url', at(P.fullV), '--bid-attestation', 'true']);
    spawnServer('provider', 'src/systems/credential-provider.js',
        ['--port', String(P.prov), '--user-pubkey', userPubkey]);
    spawnServer('mpp', 'src/systems/mpp-server.js',
        ['--port', String(P.mpp), '--user-pubkey', userPubkey]);
    spawnServer('ap2-agent', 'src/systems/ap2-only/agent-server.js',
        ['--port', String(P.ap2A), '--merchant-url', at(P.ap2M), '--verifier-url', at(P.fullV),
            '--provider-url', at(P.prov), '--mpp-url', at(P.mpp)]);
    spawnServer('ap2e-agent', 'src/systems/full/agent-server.js',
        ['--port', String(P.fullA), '--merchant-url', at(P.fullM), '--verifier-url', at(P.fullV),
            '--provider-url', at(P.prov), '--mpp-url', at(P.mpp)]);

    await waitReady('ap2-merchant', P.ap2M);
    await waitReady('verifier', P.fullV);
    await waitReady('ap2e-merchant', P.fullM);
    await waitReady('provider', P.prov);
    await waitReady('mpp', P.mpp);
    await waitReady('ap2-agent', P.ap2A);
    await waitReady('ap2e-agent', P.fullA);
}

async function main() {
    console.log(`═══ Statistical Benchmark ═══`);
    console.log(`Groups per combination: ${GROUPS}`);
    console.log(`Merchant sizes: ${MERCHANT_SIZES.join(',')}`);
    console.log(`n values: ${NBITS.join(',')}`);
    console.log(`Seed: ${SEED == null ? 'random (unseeded)' : SEED}`);
    console.log(`Output: ${OUTPUT}\n`);

    const allRecords = [];
    const totalCombinations = MERCHANT_SIZES.length * NBITS.length;
    let comboIdx = 0;

    // One enrolled user for the whole run; the parties are long-lived processes.
    const userKp = keys.generateKeypair();
    await startServers(userKp.pk, [100, 200, 300, 400]);

    for (const nM of MERCHANT_SIZES) {
        for (const n of NBITS) {
            comboIdx++;
            const scenarios = generateScenarios(nM, GROUPS);
            console.log(`[${comboIdx}/${totalCombinations}] |S|=${nM} n=${n} — ${GROUPS} groups`);
            let gi = 0;
            for (const s of scenarios) {
                gi++;
                process.stdout.write(`  [${gi}/${GROUPS}] ${s.id}: quotes=[${s.quotes.slice(0,4).join(',')}${s.quotes.length>4?'…':''}] limit=${s.limit}  `);
                await setQuotes(P.ap2M, s.quotes);
                await setQuotes(P.fullM, s.quotes);
                const record = await benchmarkOne(s, n, userKp);
                if (record.error) {
                    console.log(`ERROR: ${record.error}`);
                } else {
                    const a = record.systems.ap2Only;
                    const f = record.systems.full;
                    console.log(`ap2=${a.tTotal}ms full=${f.tTotal}ms(${f.allPass?'✓':'✗'}) proofs=${f.nProofs}`);
                }
                allRecords.push(record);
                // Incremental write: survive crashes, keep partial results
                const partial = {
                    meta: { generated: new Date().toISOString(), groups: GROUPS, merchantSizes: MERCHANT_SIZES,
                            nbits: NBITS, seed: SEED, totalScenarios: allRecords.filter(r => !r.error).length,
                            totalErrors: allRecords.filter(r => r.error).length },
                    raw: allRecords,
                };
                fs.writeFileSync(OUTPUT, JSON.stringify(partial, null, 2));
            }
            console.log('');
        }
    }

        stopServers();
    await sleep(200);

    // ---- Compute summary statistics ----
    const summary = [];
    for (const nM of MERCHANT_SIZES) {
        for (const n of NBITS) {
            const records = allRecords.filter(r =>
                r.nMerchants === nM && r.n === n && !r.error &&
                r.systems.ap2Only && r.systems.full);

            if (!records.length) continue;

            const get = (sys, key) => records.map(r => r.systems[sys][key]).filter(v => v != null);

            // Per-system stats
            for (const sys of ['ap2Only', 'full']) {
                const metrics = {};
                const keys = Object.keys(records[0].systems[sys]).filter(k => typeof records[0].systems[sys][k] === 'number');
                for (const k of keys) {
                    const vals = get(sys, k);
                    metrics[k] = { mean: avg(vals), std: std(vals), min: Math.min(...vals), max: Math.max(...vals), n: vals.length };
                }
                summary.push({ nMerchants: nM, n, system: sys, metrics, count: records.length });
            }
        }
    }

    // ---- Write output ----
    const output = {
        meta: {
            generated: new Date().toISOString(),
            groups: GROUPS,
            merchantSizes: MERCHANT_SIZES,
            nbits: NBITS,
            seed: SEED,
            totalScenarios: allRecords.filter(r => !r.error).length,
            totalErrors: allRecords.filter(r => r.error).length,
        },
        raw: allRecords,
        summary,
    };

    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));
    console.log(`\n✓ Results written to ${OUTPUT} (${(fs.statSync(OUTPUT).size / 1024).toFixed(1)} KB)`);

    // ---- Print summary table ----
    console.log('\n═══ Summary Statistics ═══\n');

    for (const s of summary) {
        const sysName = s.system === 'ap2Only' ? 'AP2-Only' : 'Full';
        const m = s.metrics;
        console.log(`|S|=${s.nMerchants}  n=${s.n}  ${sysName}  (N=${s.count})`);

        const printRow = (label, key, unit) => {
            if (!m[key]) return;
            console.log(`  ${label.padEnd(24)} ${String(m[key].mean).padStart(8)} ${unit.padEnd(4)}  (±${String(m[key].std || 0).padStart(6)} ${unit})  [${m[key].min}, ${m[key].max}]`);
        };

        if (s.system === 'ap2Only') {
            printRow('Build open mandates', 'tBuild', 'ms');
            printRow('User signatures (2)', 'tSign', 'ms');
            printRow('Merchant sign (max)', 'tMerchantSignMax', 'ms');
            printRow('Agent: fetch offers', 'tQuotesCorrected', 'ms');
            printRow('Agent: sign closed (2)', 'tBuildClosed', 'ms');
            printRow('Merchant: verify', 'tMerchantVerify', 'ms');
            printRow('CP: verify + token', 'tCp', 'ms');
            printRow('MPP: verify + settle', 'tMpp', 'ms');
            printRow('Total E2E', 'tTotal', 'ms');
            printRow('Sig size', 'sigBytes', 'B');
            printRow('Mandate size', 'mandateBytes', 'B');
        } else {
            printRow('User crypto', 'tUserCrypto', 'ms');
            printRow('Sign', 'tSign', 'ms');
            printRow('Consistency proofs', 'tInquiryProve', 'ms');
            printRow('Verify consistency', 'tInquiryVerify', 'ms');
            printRow('Response accounting', 'tAccounting', 'ms');
            printRow('Consistency proof size', 'inquiryProofBytes', 'B');
            printRow('Price-proof gen (max)', 'tPriceProofGen', 'ms');
            if (ZKP_MODE === 'single') {
                printRow('  - min', 'tPriceProofMin', 'ms');
                printRow('  - max', 'tPriceProofMax', 'ms');
                printRow('Prove (total)', 'tProve', 'ms');
                printRow('  - infeasible', 'tProveInfeasible', 'ms');
                printRow('  - feasible', 'tProveFeasible', 'ms');
                printRow('  - optimality', 'tProveOptimality', 'ms');
                printRow('Verify (total)', 'tVerify', 'ms');
                printRow('  - min', 'tVerifyPriceValidityMin', 'ms');
                printRow('  - max', 'tVerifyPriceValidityMax', 'ms');
                printRow('  - infeasible', 'tVerifyInfeasible', 'ms');
                printRow('  - feasible', 'tVerifyFeasible', 'ms');
                printRow('  - optimality', 'tVerifyOptimality', 'ms');
            } else {
                printRow('Prove', 'tProve', 'ms');
                printRow('Verify (total)', 'tVerify', 'ms');
                printRow('  - price-validity', 'tVerifyPriceValidity', 'ms');
                printRow('  - agent agg', 'tVerifyAgent', 'ms');
            }
            printRow('Total E2E', 'tTotal', 'ms');
            printRow('Proof size', 'proofBytes', 'B');
            printRow('Sig size', 'sigBytes', 'B');
            printRow('Mandate size', 'mandateBytes', 'B');
            printRow('# Proofs (total)', 'nProofs', '');
            printRow('  - price-validity', 'nPriceValidity', '');
            if (ZKP_MODE !== 'single') printRow('  - agent agg', 'nAgentProof', '');
            printRow('# diffs: infeasible', 'nInfeasible', '');
            printRow('# diffs: feasible', 'nFeasible', '');
            printRow('# diffs: optimality', 'nOptimality', '');
        }
        console.log('');
    }

    console.log('Done.');
    process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
