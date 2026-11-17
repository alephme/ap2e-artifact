// RQ1, AP2-E half: can a deviating agent complete a purchase under the range-proof
// prototype?
//
// The companion script (ap2-deviations.js) shows that plain AP2 authorises every
// deviation. Here we run the same deviations against the prototype and check whether
// the verifier accepts the evidence the agent submits:
//
//   none               honest execution (control)
//   bid-equivocation   the agent commits to different buyer bids for different merchants
//   offer-exclusion    the agent drops the cheapest offer from the comparison evidence
//   biased-selection   the agent selects a feasible but non-cheapest offer
//
// For each deviation we record whether the purchase was authorised and which check
// rejected it.
//
// Usage: node scripts/ap2e-deviations.js [--seed 42] [--reps 50] [--merchants 8,16,32]

const { start: startMerchant } = require('../src/systems/merchant-server');
const { start: startVerifier } = require('../src/systems/verifier-server');
const { start: startProvider } = require('../src/systems/credential-provider');
const { start: startMpp } = require('../src/systems/mpp-server');
const { start: startFullAgent } = require('../src/systems/full/agent-server');
const keys = require('../src/mandates/keys');
const mandate = require('../src/mandates/mandate');
const c = require('../src/crypto/c-backend');
const { hexToPoint } = require('../src/shopping/commitments');
const ecies = require('../src/crypto/ecies');

const DEVILATIONS = ['none', 'bid-equivocation', 'offer-exclusion', 'biased-selection'];
const N_BITS = 16;
// Same offer/limit generation as the overhead experiment (scripts/benchmark.js).
const PRICE_MIN = 10;
const PRICE_MAX = 500;

// Draw one scenario: quotes uniform in [PRICE_MIN, PRICE_MAX], limit at a uniformly
// chosen index in [30%, 70%] of the sorted quotes plus a small jitter. Retried until at
// least two offers fall below the limit, so a second feasible choice exists.
function drawScenario(m, rng) {
    for (let attempt = 0; attempt < 200; attempt++) {
        const quotes = Array.from({ length: m },
            () => PRICE_MIN + Math.floor(rng() * (PRICE_MAX - PRICE_MIN + 1)));
        const sorted = [...quotes].sort((a, b) => a - b);
        const lo = Math.floor(m * 0.3);
        const hi = Math.floor(m * 0.7);
        const pctIdx = lo + Math.floor(rng() * (hi - lo + 1));
        const limit = Math.max(sorted[pctIdx] + Math.floor(rng() * 11) - 5, sorted[0] - 1);
        // The agent chooses its quote; we draw one uniformly from (0, limit). All four
        // variants of this repetition share the scenario, quote included.
        const quote = 1 + Math.floor(rng() * Math.max(1, limit - 1));
        const feasible = quotes.filter((p) => p < limit);
        const accepting = quotes.filter((p) => p <= quote);
        if (feasible.length >= 2 && accepting.length >= 1) return { quotes, limit, quote };
    }
    return null;
}

function arg(name, dflt) {
    const i = process.argv.indexOf(`--${name}`);
    return i >= 0 ? process.argv[i + 1] : dflt;
}

function rng(seed) {
    let s = seed >>> 0;
    return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
}

const PORT = { merchant: 18510, verifier: 18590, provider: 18591, mpp: 18595, agent: 18501 };
const url = (p) => `http://localhost:${p}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runOnce(userKp, allowed, limit, cheat, quote) {
    // /reset regenerates the agent's keypair, so the ECIES public key is re-fetched
    // for every run and the spending cap is sealed to the current one.
    const agentEcPub = (await (await fetch(`${url(PORT.agent)}/pubkey`)).json()).eciesPubkey;
    // User side: commit to the spending cap and seal the opening for the agent.
    const blind = c.randomBlind();
    const cmt = c.commit(blind, limit);
    const sealed = await ecies.encrypt(hexToPoint(agentEcPub),
        JSON.stringify({ value: String(limit), blinding: blind.toString('hex') }));

    const build = await (await fetch(`${url(PORT.agent)}/build-mandate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            userPubkey: userKp.pk, userSk: userKp.sk, currency: 'USD',
            sealedMaxUnitPrice: { commitment: c.commitToHex(cmt), sealed },
            allowedMerchants: allowed,
        }),
    })).json();
    if (build.error) throw new Error('build: ' + build.error);


    return (await fetch(`${url(PORT.agent)}/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            openCheckoutPresentation: build.openCheckoutPresentation,
            openPaymentPresentation: build.openPaymentPresentation,
            userPubkey: userKp.pk, n: N_BITS, cheat, quote,
        }),
    })).json();
}

async function main() {
    const SEED = parseInt(arg('seed', '42'), 10);
    const REPS = parseInt(arg('reps', '30'), 10);
    const SIZES = arg('merchants', '4,8,16,32,64,128,192').split(',').map(Number);
    const rand = rng(SEED);

    const results = [];
    for (const m of SIZES) {
        // One merchant server hosts the m merchant identities, as in the benchmark. The
        // quote store is mutated per run, so every run draws a fresh scenario.
        const quoteStore = new Array(m).fill(100);
        const allowed = Array.from({ length: m }, (_, i) => mandate.merchant({
            id: i, name: `Merchant ${i}`, website: `https://merchant${i}.example`,
        }));

        const userKp = keys.generateKeypair();
        const verifier = await startVerifier({ port: PORT.verifier });
        const merchant = await startMerchant({ port: PORT.merchant, mode: 'sealed', quotes: quoteStore, bidAttestation: true, responseStrategy: 'reject-below-price', userPubkey: userKp.pk, providerUrl: url(PORT.verifier) });
        const provider = await startProvider({ port: PORT.provider, userPubkey: userKp.pk });
        const mpp = await startMpp({ port: PORT.mpp, userPubkey: userKp.pk });
        const agent = await startFullAgent({
            port: PORT.agent,
            merchantUrl: url(PORT.merchant), verifierUrl: url(PORT.verifier),
            providerUrl: url(PORT.provider), mppUrl: url(PORT.mpp),
        });
        await sleep(300);

        const cells = DEVILATIONS.map((cheat) => ({ m, cheat, n: 0, authorized: 0, failed: {} }));
        for (let rep = 0; rep < REPS; rep++) {
            // One scenario per repetition, shared by every variant: the honest run and
            // the three deviations see the same prices, the same limit and the same quote.
            const scenario = drawScenario(m, rand);
            if (!scenario) { for (const cell of cells) cell.n++; continue; }
            for (let i = 0; i < m; i++) quoteStore[i] = scenario.quotes[i];
            for (const cell of cells) {
                let res;
                try {
                    res = await runOnce(userKp, allowed, scenario.limit, cell.cheat, scenario.quote);
                } catch (e) {
                    cell.failed[e.message] = (cell.failed[e.message] || 0) + 1;
                    cell.n++;
                    await fetch(`${url(PORT.agent)}/reset`, { method: 'POST' });
                    continue;
                }
                cell.n++;
                if (res.error) {
                    cell.failed[`error: ${res.error}`] = (cell.failed[`error: ${res.error}`] || 0) + 1;
                    await fetch(`${url(PORT.agent)}/reset`, { method: 'POST' });
                    continue;
                }
                const v = (res.result && res.result.public && res.result.public.verification) || {};
                if (v.allPass) cell.authorized++;
                else {
                    const failed = (v.checks || []).filter((ch) => !ch.pass).map((ch) => ch.step);
                    for (const f of failed) cell.failed[f] = (cell.failed[f] || 0) + 1;
                }
                await fetch(`${url(PORT.agent)}/reset`, { method: 'POST' });
            }
        }
        for (const cell of cells) {
            results.push(cell);
            const rate = ((cell.authorized / cell.n) * 100).toFixed(1);
            const reasons = Object.entries(cell.failed).sort((a, b) => b[1] - a[1]).slice(0, 2)
                .map(([k, v]) => `${k}x${v}`).join(', ');
            console.log(`m=${m}  ${cell.cheat.padEnd(18)} authorized ${cell.authorized}/${cell.n} (${rate}%)  ${reasons}`);
        }

        await new Promise((r) => agent.close(r));
        await new Promise((r) => mpp.close(r));
        await new Promise((r) => provider.close(r));
        await new Promise((r) => verifier.close(r));
        await new Promise((r) => merchant.close(r));
        await sleep(200);
    }

    const out = {
        meta: {
            seed: SEED, reps: REPS, merchants: SIZES, nbits: N_BITS,
            priceRange: [PRICE_MIN, PRICE_MAX], limitPercentile: [30, 70],
        },
        results,
    };
    require('fs').writeFileSync('ap2e-deviation-results.json', JSON.stringify(out, null, 2));
    console.log('\n閴?written to ap2e-deviation-results.json');
}

main().catch((e) => { console.error(e); process.exit(1); });
