// Launch both demo systems on their designated ports.
// Usage: node scripts/launch-all.js [--quotes 120,95,150,130]

const { start: startMerchant } = require('../src/systems/merchant-server');
const { start: startVerifier } = require('../src/systems/verifier-server');
const { start: startProvider } = require('../src/systems/credential-provider');
const { start: startAp2Agent } = require('../src/systems/ap2-only/agent-server');
const { start: startFullAgent } = require('../src/systems/full/agent-server');
const { getArg } = require('../src/systems/common/http-utils');

const QUOTES = (getArg(process.argv, '--quotes', '120,95,150,130')).split(',').map(s => parseInt(s.trim(), 10));
const servers = [];

async function main() {
    console.log(`═══ Launching Both Systems ═══`);
    console.log(`Quotes: ${QUOTES.join(',')}\n`);

    // System 1 (AP2-Only; shares the credential provider with System 2 on port 3290)
    servers.push(await startProvider({ port: 3290 }));
    servers.push(await startMerchant({ port: 3210, mode: 'plain', quotes: QUOTES }));
    servers.push(await startAp2Agent({ port: 3201, merchantUrl: 'http://localhost:3210', providerUrl: 'http://localhost:3290' }));

    // System 2 (Full)
    servers.push(await startMerchant({ port: 3310, mode: 'sealed', quotes: QUOTES }));
    servers.push(await startVerifier({ port: 3390 }));
    servers.push(await startFullAgent({ port: 3301, merchantUrl: 'http://localhost:3310', verifierUrl: 'http://localhost:3390', providerUrl: 'http://localhost:3290' }));
    console.log(`System 1 — AP2-Only:     http://localhost:3201/ap2-only.html`);
    console.log(`System 2 — Full:          http://localhost:3301/full.html`);
    console.log(`\nPress Ctrl+C to stop all.\n`);
}

function cleanup() {
    for (const s of servers) { try { s.close(); } catch(e) {} }
    process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

main().catch(e => {
    if (e.code === 'EADDRINUSE') console.error('\nPort already in use. Kill previous run: taskkill /F /IM node.exe\n');
    else console.error(e);
    process.exit(1);
});
