// Build the evidence-size dataset: results/evidence.json.
//
// Reads the per-run records in results/phase-time.json and keeps only the evidence
// measurements (proof counts and byte sizes), dropping every timing field. This is the
// dataset behind the evidence-size table: it answers how many proofs of each kind were
// produced and how many bytes the agent submitted.
//
// Usage: node scripts/build-evidence.js
const fs = require('fs');
const path = require('path');

const RESULTS = path.join(__dirname, '..', 'results');
const src = JSON.parse(fs.readFileSync(path.join(RESULTS, 'phase-time.json'), 'utf8'));

const runs = src.runs
    .filter((r) => r.ap2e && r.ap2e.counts && r.ap2e.bytes)
    .map((r) => ({
        merchants: r.merchants,
        bits: r.bits,
        scenario: r.scenario,
        ap2: r.ap2 ? { signatures: r.ap2.signatures ?? null, bytes: r.ap2.bytes ?? null } : null,
        ap2e: { counts: r.ap2e.counts, bytes: r.ap2e.bytes },
    }));

const cells = [...new Set(runs.map((r) => r.merchants + '/' + r.bits))].sort((a, b) => {
    const [m1, b1] = a.split('/').map(Number);
    const [m2, b2] = b.split('/').map(Number);
    return m1 - m2 || b1 - b2;
});

const out = {
    meta: {
        description:
            'Evidence size of AP2 and AP2-E per run: proof counts and the bytes of the ' +
            'submitted evidence. Times are recorded separately in phase-time.json.',
        source: 'results/phase-time.json',
        seed: src.meta && src.meta.seed,
        groupsPerCell: src.meta && src.meta.groupsPerCell,
        cells: cells.map((c) => {
            const [merchants, bits] = c.split('/').map(Number);
            return { merchants, bits };
        }),
        units: {
            counts: 'number of proofs or signatures',
            bytes: 'bytes; range proofs at their binary size (546 B at l=16, 610 B at l=32), ' +
                   'each consistency argument 96 B, each signature 86 B; transport encoding excluded',
        },
        generated: new Date().toISOString(),
    },
    runs,
};

fs.writeFileSync(path.join(RESULTS, 'evidence.json'), JSON.stringify(out, null, 1) + '\n', 'utf8');
console.log('wrote results/evidence.json: ' + runs.length + ' runs, ' + cells.length + ' cells');
