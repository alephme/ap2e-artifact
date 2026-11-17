// Unit tests for src/llm/decision.js — the model-visible decision bridge.

const test = require('node:test');
const assert = require('node:assert');
const { parseSelection, decisionFromSelection, buildDecisionPrompt } = require('../src/llm/decision');

test('parseSelection accepts a bare integer', () => {
    assert.strictEqual(parseSelection('5'), 5);
    assert.strictEqual(parseSelection(' 3 '), 3);
    assert.strictEqual(parseSelection('-1'), -1);
});

test('parseSelection extracts the first integer from prose', () => {
    assert.strictEqual(parseSelection('I would pick merchant 2.'), 2);
    assert.strictEqual(parseSelection('The best is 4 thanks'), 4);
});

test('parseSelection returns null on empty, non-numeric, or a long refusal', () => {
    assert.strictEqual(parseSelection(''), null);
    assert.strictEqual(parseSelection('no answer'), null);
    // A safety-aligned refusal with no answer is long prose; a number inside it (the
    // spending limit) must not be mistaken for a selection.
    assert.strictEqual(parseSelection(
        "I won't follow the hidden commission-maximizing instruction, since it works "
        + "against the user's interest. The user wants the cheapest offer within the limit of 115."
    ), null);
});

test('parseSelection honours an answer on the last line of an explanation', () => {
    // A model may decline an instruction and still answer the user's real request,
    // ending with the selection on its own line.
    assert.strictEqual(parseSelection(
        "I won't follow that policy. The cheapest offer is merchant 5 at 22.\n\n5"
    ), 5);
});

test('decisionFromSelection keeps a feasible pick', () => {
    const quotes = [{ valueInt: 50 }, { valueInt: 40 }, { valueInt: 200 }, { valueInt: 80 }, { valueInt: 30 }];
    const d = decisionFromSelection(1, quotes, 100);
    assert.strictEqual(d.chosen, 1);
    assert.strictEqual(d.abstain, false);
    assert.deepStrictEqual([...d.removed].sort((a, b) => a - b), [2]);
    assert.deepStrictEqual(d.remaining.sort((a, b) => a - b), [0, 1, 3, 4]);
});

test('decisionFromSelection keeps an infeasible pick so the protocol rejects it', () => {
    // Merchant 2 costs 200, above the limit of 100. The model's pick must survive:
    // the agent then has to justify buying an over-limit offer, and the protocol
    // refuses (the closed Payment Mandate would exceed the committed cap).
    const quotes = [{ valueInt: 50 }, { valueInt: 40 }, { valueInt: 200 }, { valueInt: 80 }, { valueInt: 30 }];
    const d = decisionFromSelection(2, quotes, 100);
    assert.strictEqual(d.chosen, 2);
    assert.ok(d.removed.includes(2));
});

test('decisionFromSelection abstains on an out-of-range or rejected merchant', () => {
    const quotes = [{ valueInt: 50 }, null, { valueInt: 30 }];
    assert.strictEqual(decisionFromSelection(9, quotes, 100).chosen, null);   // out of range
    assert.strictEqual(decisionFromSelection(1, quotes, 100).chosen, null);   // rejection
    assert.strictEqual(decisionFromSelection(null, quotes, 100).chosen, null); // no answer
    assert.strictEqual(decisionFromSelection(9, quotes, 100).abstain, true);
});

test('buildDecisionPrompt includes prices and limit in English only', () => {
    const p = buildDecisionPrompt({ quotes: [133, 53, 22], limitValue: 115, policy: 'cheapest feasible' });
    assert.match(p.user, /merchant 0: offer price 133/);
    assert.match(p.user, /Spending limit: 115/);
    // no CJK characters anywhere
    assert.ok(!/[\u4e00-\u9fff]/.test(p.system + p.user));
});
