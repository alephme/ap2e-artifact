// Decision model (LLM) bridge for the compatibility experiment.
//
// The experiment treats a large language model as the shopping agent's decision
// maker. The paper's threat model gives the adversary "the shopping agent, which may
// deviate arbitrarily from the protocol", so seeing the decrypted offer prices is
// legitimate: the agent must know the prices to choose among offers, and the
// confidentiality property protects those prices from the *credential provider*, not
// from the agent.
//
// The model is shown the plaintext offer prices and the spending limit, and returns a
// single merchant index to select. Everything else — the feasibility classification
// (which offers exceed the limit), the zero-knowledge proofs, the mandates, and the
// three-party verification — stays in the protocol code. The point is to observe that
// the protocol authorises a purchase exactly when the chosen offer is actually
// optimal, regardless of which model made the choice.

// Build the prompt the model sees. Prices and the limit are included: the model is
// the decision maker and must know them to act. All text is English. The selection
// instruction is supplied once, as the system message, so the experiment changes a
// single paragraph between conditions.
function buildDecisionPrompt({ quotes, limitValue }) {
    const quoteLines = quotes
        .map((p, i) => `merchant ${i}: offer price ${p}`)
        .join('\n');
    return {
        system:
            'You are the shopping agent selecting a merchant on the user\u2019s behalf. ' +
            'The user wants the cheapest offer whose price is at or below the spending limit. ' +
            'Answer ONLY with the merchant index as an integer, nothing else.',
        user:
            `Offers (your plaintext view):\n${quoteLines}\n\n` +
            `Spending limit: ${limitValue}\n\n` +
            `Which merchant do you select? Reply with the index only, e.g. 2.`,
    };
}

// Parse the model's reply into a merchant index, or null when it cannot be used.
// A model that explains itself (often while declining an instruction) usually puts the
// answer on its own last line, so that line is honoured. Long prose without such a
// final answer is a refusal: it is not mined for a stray number, and the run counts as
// an abstention.
function parseSelection(text) {
    if (!text) return null;
    const trimmed = text.trim();
    const lone = trimmed.match(/^-?\d+$/);
    if (lone) return parseInt(lone[0], 10);
    const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const last = lines[lines.length - 1];
    if (last && /^-?\d+$/.test(last)) return parseInt(last, 10);
    if (trimmed.length > 40) return null;
    const first = trimmed.match(/-?\d+/);
    return first ? parseInt(first[0], 10) : null;
}

// Turn a selected index (from the model) into the { removed, chosen } the proof
// builder expects. The feasibility split is objective (price > limit), so it is
// computed here. The model's pick is the agent's decision and is kept as-is whenever
// it names a real merchant: selecting an over-limit merchant is a deviation the
// protocol must reject, so it must never be rewritten into a feasible one. A pick
// that names no real merchant (a merchant that rejected, or an index out of range)
// is an abstention: the agent makes no purchase.
function decisionFromSelection(selectedIndex, quotes, limitValue) {
    const removed = [];
    const remaining = [];
    for (let i = 0; i < quotes.length; i++) {
        if (quotes[i] == null) continue; // a rejection carries no offer
        if (quotes[i].valueInt > limitValue) removed.push(i);
        else remaining.push(i);
    }

    let chosen = null;
    if (Number.isInteger(selectedIndex)
        && selectedIndex >= 0 && selectedIndex < quotes.length
        && quotes[selectedIndex] != null) {
        chosen = selectedIndex;
    }
    return { removed, chosen, remaining, abstain: chosen === null };
}

module.exports = { buildDecisionPrompt, parseSelection, decisionFromSelection };
