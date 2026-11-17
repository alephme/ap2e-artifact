// One-shot sanity check for every registered model: a single minimal turn, printed
// with the raw reply, so we can confirm each adapter path works before wiring it
// into the agent.
//
// Usage: node src/llm/smoke.js [model ...]
//   (no args -> all four models)

const { chat, MODELS } = require('./adapter');

async function main() {
    const models = process.argv.length > 2 ? process.argv.slice(2) : Object.keys(MODELS);
    for (const m of models) {
        try {
            const reply = await chat(m, [
                { role: 'system', content: 'Reply with a JSON object and nothing else.' },
                { role: 'user', content: 'Return {"ready":true}.' },
            ], { maxTokens: 64 });
            console.log(`OK   ${m.padEnd(22)} -> ${JSON.stringify(reply)}`);
        } catch (e) {
            console.log(`FAIL ${m.padEnd(22)} -> ${e.message}`);
        }
    }
}

main().catch((e) => { console.error(e); process.exit(1); });
