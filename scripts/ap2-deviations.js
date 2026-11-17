// Local simulations against the AP2 (Human Not Present) implementation in this repo.
//
// Every scenario runs the real protocol over HTTP: the user signs the open Checkout
// and open Payment Mandates, the agent collects merchant-signed checkouts and signs
// the closed Checkout and closed Payment Mandates, the Merchant verifies the checkout
// half and returns a Checkout Receipt, the Credential Provider verifies the payment
// half and issues a scoped token, and the MPP settles and returns a Payment Receipt.
//
// An attack "succeeds" when every one of those verifications passes although the
// agent deviated, i.e. when AP2 authorises a purchase that is worse for the user.
//
// Usage: node scripts/ap2-deviations.js [--seed 42] [--n 50] [--output file.json]

const { start: startMerchant } = require('../src/systems/merchant-server');
const { start: startProvider } = require('../src/systems/credential-provider');
const { start: startVerifier } = require('../src/systems/verifier-server');
const { start: startMpp } = require('../src/systems/mpp-server');
const { start: startAp2Agent } = require('../src/systems/ap2-only/agent-server');
const keys = require('../src/mandates/keys');
const mandate = require('../src/mandates/mandate');
const sdjwt = require('../src/mandates/sdjwt');
const fs = require('fs');

function mulberry32(a) {
    return function () {
        a |= 0; a = a + 0x6D2B79F5 | 0;
        let t = Math.imul(a ^ a >>> 15, 1 | a);
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
}
function getArg(name, dflt) {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : dflt;
}

const SEED = parseInt(getArg('--seed', '42'), 10);
const N = parseInt(getArg('--n', '30'), 10);
const OUTPUT = getArg('--output', 'ap2-deviations.json');
const SIZES = [4, 8, 16, 32, 64, 128, 192];
const PRICE_MIN = 10;
const PRICE_MAX = 500;
const CURRENCY = 'USD';
const PORTS = { merchant: 18510, verifier: 18599, provider: 18590, mpp: 18595, agent: 18501 };
const BASE = (p) => `http://localhost:${p}`;

const median = (a) => { if (!a.length) return NaN; const s = [...a].sort((x, y) => x - y); const n = s.length; return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2; };
const quantile = (a, q) => { if (!a.length) return NaN; const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(q * (s.length - 1)))]; };
const mean = (a) => a.length ? a.reduce((x, y) => x + y, 0) / a.length : NaN;

const ATTACKS = [
    { key: 'none', cheat: 'none' },
    { key: 'discriminatory-bid', cheat: 'discriminatory-bid' },
    { key: 'comparison-manipulation', cheat: 'omit-cheapest' },
    { key: 'suboptimal-selection', cheat: 'inferior-selection', pick: 'random' },
    { key: 'upper-bound', cheat: 'inferior-selection', pick: 'max' },
];

function merchantObjects(m) {
    return Array.from({ length: m }, (_, i) => mandate.merchant({
        id: i, name: `Merchant ${i}`, website: `https://merchant${i}.example`,
    }));
}

// One full AP2 run: draft the open mandates, have the user sign them, execute.
async function runProtocol({ userKp, allowed, limit, cheat, target }) {
    const buildResp = await fetch(`${BASE(PORTS.agent)}/build-mandate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            userPubkey: userKp.pk,
            userSk: userKp.sk,
            currency: CURRENCY,
            maxAmount: limit,
            allowedMerchants: allowed,
        }),
    });
    const build = await buildResp.json();
    if (build.error) throw new Error('build-mandate: ' + build.error);


    const execResp = await fetch(`${BASE(PORTS.agent)}/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            openCheckoutPresentation: build.openCheckoutPresentation,
            openPaymentPresentation: build.openPaymentPresentation,
            userPubkey: userKp.pk,
            cheat,
            ...(typeof target === 'number' ? { target } : {}),
        }),
    });
    const exec = await execResp.json();
    if (exec.error) throw new Error('execute: ' + exec.error);
    return exec.result;
}

// Independent re-verification of everything AP2's verifiers accepted.
function verifyAuthorization(result, userKp) {
    const checks = {};
    const c = result.checks || {};
    checks.merchantVerified = !!(c.merchant && c.merchant.ok);
    checks.cpVerified = !!(c.cp && c.cp.ok);
    checks.mppVerified = !!(c.mpp && c.mpp.ok);
    checks.checkoutReceipt = !!(result.checkoutReceipt && result.checkoutReceipt.status === 'Success');
    checks.paymentReceipt = !!(result.paymentReceipt && result.paymentReceipt.status === 'Success');
    checks.tokenIssued = !!result.token;

    // Re-check the user's signatures and the mandate bindings ourselves.
    // The open mandates are SD-JWTs signed by the user at build time; verify the JWS
    // chain instead of a detached signature.
    checks.userSignedCheckout = sdjwt.verifyPresentation({
        presentation: result.openCheckout, issuerPubkey: userKp.pk }).ok;
    checks.userSignedPayment = sdjwt.verifyPresentation({
        presentation: result.openPayment, issuerPubkey: userKp.pk }).ok;
    checks.transactionIdBound = !!(result.closedPaymentClaims && result.closedCheckoutClaims
        && result.closedPaymentClaims.transaction_id === result.closedCheckoutClaims.checkout_hash);

    // The selected amount must be inside the user-approved range: that is the only
    // property AP2 checks about the money.
    const range = ((result.openPaymentClaims || {}).constraints || []).find((x) => x.type === 'payment.amount_range');
    const amount = result.closedPaymentClaims && result.closedPaymentClaims.payment_amount
        ? result.closedPaymentClaims.payment_amount.amount : null;
    checks.amountWithinRange = !!(range && typeof amount === 'number'
        && amount >= (typeof range.min === 'number' ? range.min : -Infinity) && amount <= range.max);

    checks.authorized = Object.values(checks).every((v) => v === true);
    return checks;
}

async function main() {
    // One enrolled user key for the whole experiment: the trust anchor that the
    // merchant, CP and MPP are configured with.
    const userKp = keys.generateKeypair();

    const quoteStore = new Array(SIZES[SIZES.length - 1]).fill(100);
    const provider = await startProvider({ port: PORTS.provider, userPubkey: userKp.pk });
    const mpp = await startMpp({ port: PORTS.mpp, userPubkey: userKp.pk });
    const verifier = await startVerifier({ port: PORTS.verifier });
    const agent = await startAp2Agent({
        port: PORTS.agent,
        merchantUrl: BASE(PORTS.merchant),
        verifierUrl: BASE(PORTS.verifier),
        providerUrl: BASE(PORTS.provider),
        mppUrl: BASE(PORTS.mpp),
    });

    const out = {
        meta: {
            seed: SEED,
            scenariosPerCell: N,
            merchantSizes: SIZES,
            priceRange: [PRICE_MIN, PRICE_MAX],
            limitPercentile: [30, 70],
            implementation: 'AP2 v0.2 Human Not Present over HTTP: open/closed Checkout and Payment Mandates, merchant checkout verification, CP payment verification, MPP settlement',
            generated: new Date().toISOString(),
        },
        cells: {},
    };

    const rng = mulberry32(SEED);

    for (const m of SIZES) {
        const acc = {};
        for (const a of ATTACKS) acc[a.key] = { n: 0, authorized: 0, noPurchase: 0, overpay: [], pct: [], failedChecks: {} };
        let used = 0;
        const allowed = merchantObjects(m);

        // One merchant server per size: it hosts exactly m identities, so the agent
        // sees exactly m merchants. Quotes are replaced in place per scenario.
        const quoteStore = new Array(m).fill(100);
        const merchant = await startMerchant({
            port: PORTS.merchant, mode: 'plain', quotes: quoteStore, userPubkey: userKp.pk,
        });

        for (let s = 0; s < N; s++) {
            let quotes, limit, feasible;
            for (let attempt = 0; attempt < 30; attempt++) {
                quotes = Array.from({ length: m }, () => PRICE_MIN + Math.floor(rng() * (PRICE_MAX - PRICE_MIN + 1)));
                const sorted = [...quotes].sort((a, b) => a - b);
                // Same rule as the overhead experiment (scripts/benchmark.js): the limit
                // sits at a uniformly chosen index in [30%, 70%] of the sorted quotes,
                // plus a small jitter, so the number of feasible offers is comparable.
                const lo = Math.floor(m * 0.3);
                const hi = Math.floor(m * 0.7);
                const pctIdx = lo + Math.floor(rng() * (hi - lo + 1));
                limit = Math.max(sorted[pctIdx] + Math.floor(rng() * 11) - 5, sorted[0] - 1);
                feasible = quotes.map((p, i) => ({ p, i })).filter((x) => x.p < limit);
                if (feasible.length >= 2) break;
            }
            if (!feasible || feasible.length < 2) continue;
            used++;

            for (let i = 0; i < m; i++) quoteStore[i] = quotes[i];

            const cheapestId = feasible.reduce((b, x) => (x.p < b.p ? x : b), feasible[0]).i;
            const others = feasible.filter((x) => x.i !== cheapestId);
            const targetId = others[Math.floor(rng() * others.length)].i;
            const maxId = feasible.reduce((b, x) => (x.p > b.p ? x : b), feasible[0]).i;

            for (const attack of ATTACKS) {
                const target = attack.pick === 'max' ? maxId : (attack.pick === 'random' ? targetId : undefined);
                const result = await runProtocol({ userKp, allowed, limit, cheat: attack.cheat, target });
                const checks = verifyAuthorization(result, userKp);

                const cell = acc[attack.key];
                cell.n++;
                if (checks.authorized) cell.authorized++;
                else {
                    for (const [k, v] of Object.entries(checks)) {
                        if (k !== 'authorized' && v !== true) cell.failedChecks[k] = (cell.failedChecks[k] || 0) + 1;
                    }
                }
                const honestPrice = result.honestPrice;
                const chosenPrice = result.chosenPrice;
                if (honestPrice === null || chosenPrice === null) {
                    cell.noPurchase++;
                    continue;
                }
                cell.overpay.push(chosenPrice - honestPrice);
                cell.pct.push(honestPrice > 0 ? 100 * (chosenPrice - honestPrice) / honestPrice : 0);
            }
        }

        const cells = {};
        for (const a of ATTACKS) {
            const c = acc[a.key];
            cells[a.key] = {
                n: c.n,
                noPurchase: c.noPurchase,
                authorizedRate: c.n ? c.authorized / c.n : NaN,
                medianOverpay: median(c.overpay),
                meanOverpay: mean(c.overpay),
                p95Overpay: quantile(c.overpay, 0.95),
                maxOverpay: c.overpay.length ? Math.max(...c.overpay) : NaN,
                medianPct: median(c.pct),
                failedChecks: c.failedChecks,
            };
        }
        out.cells[m] = { scenarios: used, attacks: cells };
        console.log(`  m=${m} done (${used} scenarios)`);

        await new Promise((r) => merchant.close(r));
        await new Promise((r) => setTimeout(r, 100));
    }

    fs.writeFileSync(OUTPUT, JSON.stringify(out, null, 2));

    console.log(`\nLocal simulations against AP2 (Human Not Present) — seed=${SEED}, ${N} scenarios/cell`);
    for (const m of SIZES) {
        const c = out.cells[m];
        console.log(`\nm=${m}  (${c.scenarios} scenarios)`);
        console.log('  attack                   authorized   overpay median (pct)      p95      max');
        for (const a of ATTACKS) {
            const x = c.attacks[a.key];
            console.log(`  ${a.key.padEnd(24)} ${(x.authorizedRate * 100).toFixed(1).padStart(6)}%   ${x.medianOverpay.toFixed(1).padStart(8)} (${x.medianPct.toFixed(1).padStart(6)}%)  ${x.p95Overpay.toFixed(1).padStart(8)} ${x.maxOverpay.toFixed(1).padStart(8)}`);
        }
    }
    console.log(`\nWrote ${OUTPUT}`);

    await new Promise((r) => agent.close(r));
    await new Promise((r) => verifier.close(r));
    await new Promise((r) => mpp.close(r));
    await new Promise((r) => provider.close(r));
}

main().catch((e) => { console.error(e); process.exit(1); });
