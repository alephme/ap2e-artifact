// Shared HTTP server utilities (CORS, JSON parsing, etc.).
const http = require('http');
const fs = require('fs');
const path = require('path');

// ----- CORS -----
function cors(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ----- JSON -----
function sendJSON(res, status, obj) {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
                            'access-control-allow-origin': '*' });
    res.end(JSON.stringify(obj));
}

function readJSON(req, maxBytes) {
    // The cap is a prototype guard, not a protocol limit: at large merchant counts the
    // evidence carried by a closed mandate exceeds 1 MB, and destroying the connection
    // would surface as an unreachable party rather than a refusal. MAX_BODY_BYTES
    // raises it for runs with many merchants.
    const cap = maxBytes || Number(process.env.MAX_BODY_BYTES || 1024 * 1024);
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk;
            if (body.length > cap) {
                req.destroy();
                reject(new Error('Request body too large'));
            }
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (e) {
                reject(new Error('Invalid JSON: ' + e.message));
            }
        });
        req.on('error', reject);
    });
}

// ----- Static file serving -----
const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
};

function serveStatic(rootDir, urlPath, res) {
    // Normalize to prevent path traversal
    const filePath = path.normalize(path.join(rootDir, urlPath === '/' ? 'index.html' : urlPath));
    if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        return res.end('Forbidden');
    }
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
            return res.end('Not Found');
        }
        res.writeHead(200, {
            'content-type': MIME[path.extname(filePath)] || 'application/octet-stream',
            'access-control-allow-origin': '*',
        });
        res.end(data);
    });
}

// ----- Arg parsing -----
function getArg(argv, name, defaultValue) {
    const idx = argv.indexOf(name);
    if (idx >= 0 && idx + 1 < argv.length) return argv[idx + 1];
    return defaultValue;
}

// ----- Create server -----
function createServer(rootDir) {
    return http.createServer((req, res) => {
        // Handle CORS preflight
        if (req.method === 'OPTIONS') {
            cors(res);
            res.writeHead(204);
            return res.end();
        }
        return serveStatic(rootDir, decodeURIComponent(req.url.split('?')[0]), res);
    });
}

module.exports = { cors, sendJSON, readJSON, serveStatic, MIME, getArg, createServer };
