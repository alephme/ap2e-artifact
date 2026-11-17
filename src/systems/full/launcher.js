// Full System Launcher — starts all servers for System (3).
// Usage: node src/systems/full/launcher.js [--quotes 120,95,150,130]

const { start: startMerchant } = require('../merchant-server');
const { start: startVerifier } = require('../verifier-server');
const { start: startProvider } = require('../credential-provider');
const { start: startAgent } = require('./agent-server');
const { getArg } = require('../common/http-utils');

const QUOTES = (getArg(process.argv, '--quotes', '120,95,150,130')).split(',').map(s => parseInt(s.trim(), 10));

const servers = [];

async function main() {
    console.log(`═══ Full System (AP2 + ZKP) ═══`);
    console.log(`Quotes: ${QUOTES.join(',')}\n`);

    try {
        servers.push(await startMerchant({ port: 3310, mode: 'sealed', quotes: QUOTES }));
        servers.push(await startVerifier({ port: 3390 }));
        servers.push(await startProvider({ port: 3290 }));
        servers.push(await startAgent({ port: 3301, merchantUrl: 'http://localhost:3310', verifierUrl: 'http://localhost:3390', providerUrl: 'http://localhost:3290' }));
    } catch (e) {
        if (e.code === 'EADDRINUSE') {
            console.error('\nPort already in use. Kill previous run: taskkill /F /IM node.exe\n');
        } else {
            console.error(e);
        }
        process.exit(1);
    }

    console.log(`\nDemo UI:  http://localhost:3301/full.html`);
    console.log('Press Ctrl+C to stop.\n');
}

function cleanup() {
    for (const s of servers) { try { s.close(); } catch(e) {} }
    process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
process.on('exit', cleanup);

main().catch(e => {
    if (e.code === 'EADDRINUSE') console.error('\nPort already in use. Kill previous run: taskkill /F /IM node.exe\n');
    else console.error(e);
    process.exit(1);
});
