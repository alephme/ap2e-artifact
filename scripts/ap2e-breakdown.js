// Account for AP2-E's end-to-end time in the same units as tab:compute.
//
// The table lists per-party phases; this script measures the phases it does not list
// (offer round, closed mandates, CP, MPP, kb-jwt/serialisation) so the rows add up to
// the measured end-to-end time.
//
// Usage: node scripts/ap2e-breakdown.js [--merchants 4] [--nbits 16] [--reps 30]

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

const P = { merchant: 18910, verifier: 18990, provider: 18991, mpp: 18995, agent: 18901 };
const U = (p) => `http://localhost:${p}`;
const arg = (name, dflt) => {
    const i = process.argv.indexOf(`--${name}`);
    return i >= 0 ? process.argv[i + 1] : dflt;
};
const median = (a) => {
    const s = [...a].sort((x, y) => x - y);
    const n = s.length;
    return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
};

(async () => {
    const m = parseInt(arg('merchants', '4'), 10);
    const n = parseInt(arg('nbits', '16'), 10);
    const reps = parseInt(arg('reps', '30'), 10);
    const limit = 140;
    const quotes = Array.from({ length: m }, (_, i) => 60 + i * 20);
    const allowed = quotes.map((_, i) => mandate.merchant({ id: i, name: `M${i}`, website: `https://m${i}` }));

    await startMerchant({ port: P.merchant, mode: 'sealed', quotes });
    await startVerifier({ port: P.verifier });
    await startProvider({ port: P.provider });
    await startMpp({ port: P.mpp, userPubkey: null });
    await startFullAgent({
        port: P.agent, merchantUrl: U(P.merchant), verifierUrl: U(P.verifier),
        providerUrl: U(P.provider), mppUrl: U(P.mpp),
    });

    const rows = [];
    for (let it = 0; it < reps; it++) {
        const userKp = keys.generateKeypair();
        const pk = (await (await fetch(`${U(P.agent)}/pubkey`)).json()).eciesPubkey;
        const blind = c.randomBlind();
        const cmt = c.commit(blind, limit);
        const sealed = await ecies.encrypt(hexToPoint(pk), JSON.stringify({ value: String(limit), blinding: blind.toString('hex') }));

        const t0 = performance.now();
        const build = await (await fetch(`${U(P.agent)}/build-mandate`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userPubkey: userKp.pk, userSk: userKp.sk, currency: 'USD',
                sealedMaxUnitPrice: { commitment: c.commitToHex(cmt), sealed },
                allowedMerchants: allowed,
            }),
        })).json();
        const tBuild = performance.now() - t0;

        const t1 = performance.now();
        const exec = await (await fetch(`${U(P.agent)}/execute`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                openCheckoutPresentation: build.openCheckoutPresentation,
                openPaymentPresentation: build.openPaymentPresentation,
                userPubkey: userKp.pk, n,
            }),
        })).json();
        const tExec = performance.now() - t1;
        if (exec.error) { console.error('execute:', exec.error); break; }
        rows.push({ tBuild, tExec, tm: exec.result.public.timingMs, v: exec.result.public.verification.timingMs || {} });
        await fetch(`${U(P.agent)}/reset`, { method: 'POST' });
    }

    const md = (fn) => +median(rows.map(fn)).toFixed(1);
    const out = {
        m, n, reps: rows.length,
        build: md((r) => r.tBuild),
        exec: md((r) => r.tExec),
        internal: md((r) => r.tm.total),
        userCommitEncrypt: md((r) => (r.tm.userCommit || 0) + (r.tm.userEncrypt || 0)),
        quotes: md((r) => r.tm.quotes || 0),
        prove: md((r) => r.tm.prove || 0),
        bidProve: md((r) => r.tm.bidProve || 0),
        buildClosed: md((r) => r.tm.buildClosed || 0),
        verifyRound: md((r) => r.tm.verify || 0),
        verifierMandates: md((r) => r.v.mandates || 0),
        verifierZkp: md((r) => r.v.zkp || 0),
        verifierBid: md((r) => r.v.bidVerify || 0),
        cp: md((r) => r.tm.cp || 0),
        mpp: md((r) => r.tm.mpp || 0),
    };
    // kb-jwt + JSON + everything else
    const accounted = out.quotes + out.prove + out.bidProve + out.buildClosed
        + out.verifyRound + out.cp + out.mpp;
    out.unaccounted = +(out.internal - accounted).toFixed(1);
    console.log(JSON.stringify(out, null, 1));
    process.exit(0);
})();
