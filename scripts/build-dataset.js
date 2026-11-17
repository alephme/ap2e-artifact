// Merge the per-cell benchmark files into one formatted dataset: results/phase-time.json.
//
// Input : results/*.json files written by scripts/benchmark.js (one per cell, meta + raw[])
// Output: results/phase-time.json
//
// Every run keeps the AP2 and AP2-E phases plus the evidence counts and bytes, so the
// phase table, the evidence table and the scalability figure all read from one file.
const fs = require('fs');
const path = require('path');

const RESULTS = path.join(__dirname, '..', 'results');

const med = (a) => {
    const s = [...a].sort((x, y) => x - y);
    const n = s.length;
    if (!n) return NaN;
    const m = n >> 1;
    return n % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const r1 = (x) => (typeof x === 'number' && Number.isFinite(x) ? +x.toFixed(1) : null);

function oneRun(row) {
    const m = row.nMerchants;
    const ap2 = row.systems.ap2Only || {};
    const full = row.systems.full || {};
    const fold = (raw, block) => (raw == null || block == null ? null : raw - (block - block / m));
    return {
        scenario: row.scenario,
        quotes: row.quotes,
        limit: row.limit,
        ap2: {
            e2eRawMs: ap2.tTotalRaw ?? null,
            e2eMs: fold(ap2.tTotalRaw, ap2.tQuotes),
            buildMs: ap2.tBuild ?? null,
            signMs: ap2.tSign ?? null,
            quotesMs: ap2.tQuotes ?? null,
            buildClosedMs: ap2.tBuildClosed ?? null,
            merchantVerifyMs: ap2.tMerchantVerify ?? null,
            cpMs: ap2.tCp ?? null,
            mppMs: ap2.tMpp ?? null,
            signatures: ap2.nSignatures ?? null,
        },
        ap2e: {
            e2eRawMs: full.tTotalSerialized ?? null,
            e2eMs: fold(full.tTotalSerialized, full.tQuoteBlock),
            merchantBlockMs: full.tQuoteBlock ?? null,
            priceProofMs: full.tPriceProofGen ?? null,
            encryptMs: full.tMerchantEncrypt ?? null,
            classificationProofMs:
                (full.tProveInfeasible || 0) + (full.tProveFeasible || 0) || null,
            optimalityProofMs: full.tProveOptimality ?? null,
            consistencyProofMs: full.tInquiryProve ?? null,
            verifyPriceMs: full.tVerifyPriceAtCollection ?? null,
            verifyClassificationMs:
                (full.tVerifyInfeasible || 0) + (full.tVerifyFeasible || 0) || null,
            verifyOptimalityMs: full.tVerifyOptimality ?? null,
            verifyConsistencyMs: full.tInquiryVerify ?? null,
            merchantVerifyMs: full.tMerchantVerifyFull ?? null,
            cpMs: full.tCpFull ?? null,
            mppMs: full.tMppFull ?? null,
            counts: {
                priceValidity: full.nPriceValidity ?? null,
                infeasible: full.nInfeasibleProofs ?? null,
                feasible: full.nFeasibleProofs ?? null,
                optimality: full.nOptimalityProofs ?? null,
                consistency: full.inquiryN ?? null,
            },
            bytes: {
                proofs: full.proofBytes ?? null,
                consistency: full.inquiryProofBytes ?? null,
                signatures: full.sigBytes ?? null,
                mandates: full.mandateBytes ?? null,
            },
        },
    };
}

// One benchmark invocation covers every merchant count and proof width, so the input is
// a single file whose rows are tagged with their cell (row.nMerchants, row.n).
const INPUT = path.join(RESULTS, 'benchmark.json');
if (!fs.existsSync(INPUT)) {
    throw new Error(
        'results/benchmark.json not found. Run:\n' +
        '  node scripts/benchmark.js --groups 30 --merchants 4,8,16,32,64,128,192 ' +
        '--nbits 16,32 --seed 100 --output results/benchmark.json');
}
const data = JSON.parse(fs.readFileSync(INPUT, 'utf8'));

const runs = [];
const cells = new Set();
for (const row of data.raw) {
    if (!row.systems || !row.systems.full || !(row.systems.full.tTotalSerialized > 0)) continue;
    const m = row.nMerchants;
    const bits = row.n;
    cells.add(`${m}/${bits}`);
    runs.push({ merchants: m, bits, ...oneRun(row) });
}
const metas = [data.meta];

runs.sort((a, b) => a.merchants - b.merchants || a.bits - b.bits || a.scenario - b.scenario);

const machine = metas.find((m) => m.machine)?.machine || 'AWS EC2 i4i.large, 2 vCPU, Ubuntu 26.04, Node 20.18.1';
const out = {
    meta: {
        description:
            'Phase latency and evidence size of AP2 and AP2-E over merchant counts and proof widths. ' +
            'Each cell holds 30 runs on one shared scenario set (seed 100).',
        machine,
        seed: metas[0].seed ?? 100,
        groupsPerCell: metas[0].groups ?? 30,
        cells: [...cells].sort((x, y) => {
            const [m1, b1] = x.split('/').map(Number);
            const [m2, b2] = y.split('/').map(Number);
            return m1 - m2 || b1 - b2;
        }).map((c) => {
            const [merchants, bits] = c.split('/').map(Number);
            return { merchants, bits };
        }),
        units: {
            time: 'milliseconds',
            bytes: 'bytes',
            note: 'e2eMs divides the merchant block by the merchant count; e2eRawMs is the raw wall clock.',
        },
        generated: new Date(metas[0].generated || Date.now()).toISOString(),
    },
    runs,
};

fs.writeFileSync(path.join(RESULTS, 'phase-time.json'), JSON.stringify(out, null, 1) + '\n', 'utf8');
console.log(`wrote results/phase-time.json: ${runs.length} runs, ${cells.size} cells`);
