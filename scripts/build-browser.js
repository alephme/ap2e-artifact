// esbuild build script for browser crypto bundle.
const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');

const entry = path.join(__dirname, '..', 'src', 'browser', 'entry.js');
const outfile = path.join(__dirname, '..', 'src', 'web', 'shared', 'crypto-bundle.js');

const result = esbuild.buildSync({
    entryPoints: [entry],
    bundle: true,
    format: 'iife',
    globalName: 'ZKP',
    platform: 'browser',
    target: 'es2020',
    outfile,
    minify: false,
    sourcemap: false,
});

if (result.errors.length > 0) {
    console.error('Bundle errors:', result.errors);
    process.exit(1);
}
if (result.warnings.length > 0) {
    console.warn('Bundle warnings:', result.warnings);
}

const sizeKB = (fs.statSync(outfile).size / 1024).toFixed(1);
console.log(`✓ Browser crypto bundle: ${outfile} (${sizeKB} KB)`);
