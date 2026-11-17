// Unit tests for the SD-JWT primitives (docs/sdjwt-contract.md section 1):
// JWS compact serialisation with ES256K, disclosures, presentations and kb-sd-jwt.
//
// Covers the happy path plus every rejection required by the contract: invalid
// JWS signature, wrong _sd_alg, an uncommitted disclosure, duplicate
// disclosures, overriding a non-disclosable claim, missing requiredClaims, and
// kb-jwt nonce / aud / sd_hash mismatches.

const test = require('node:test');
const assert = require('node:assert');
const { createHash } = require('crypto');

const keys = require('../src/mandates/keys');
const sdjwt = require('../src/mandates/sdjwt');
const { base64url, base64urlDecode } = require('../src/mandates/hashes');

// ---- fixtures ----

function makeWorld() {
    const issuer = keys.generateKeypair();
    const holder = keys.generateKeypair();
    const claims = {
        vct: 'mandate.checkout.open.1',
        iss: issuer.pk,
        iat: 1700000000,
        constraints: { allowed_merchants: [0] },
        payment_amount: 12000,
    };
    const issued = sdjwt.issueSdJwt({
        claims,
        disclosable: ['constraints', 'payment_amount'],
        skHex: issuer.sk,
    });
    return { issuer, holder, claims, issued };
}

function allDisclosures(w) {
    return sdjwt.present({ sdjwt: w.issued.sdjwt, disclosures: w.issued.disclosures });
}

function b64uJson(value) {
    return base64url(Buffer.from(JSON.stringify(value), 'utf8'));
}

// base64url(SHA-256(presentation)), computed independently of the module.
function sdHash(presentation) {
    return base64url(createHash('sha256').update(presentation, 'utf8').digest());
}

// ---- JWS ----

test('signJws/verifyJws round-trip preserves header and payload', () => {
    const { issuer } = makeWorld();
    const payload = { sub: 'alice', iat: 1700000000, data: { nested: [1, 2, 3] } };
    const jws = sdjwt.signJws(payload, issuer.sk);

    const verified = sdjwt.verifyJws(jws, issuer.pk);
    assert.strictEqual(verified.ok, true);
    assert.deepStrictEqual(verified.header, { alg: 'ES256K', typ: 'JWT' });
    assert.deepStrictEqual(verified.payload, payload);

    // Compact serialisation: three base64url segments, no padding.
    const parts = jws.split('.');
    assert.strictEqual(parts.length, 3);
    for (const part of parts) assert.match(part, /^[A-Za-z0-9_-]+$/);

    const rawSignature = base64urlDecode(parts[2]);
    assert.strictEqual(rawSignature.length, 64, 'signature must be 64-byte r||s');
});

test('decodeJws exposes header, payload, signingInput and signature without verifying', () => {
    const { issuer } = makeWorld();
    const jws = sdjwt.signJws({ sub: 'bob' }, issuer.sk);
    const parts = jws.split('.');
    const decoded = sdjwt.decodeJws(jws);

    assert.strictEqual(decoded.signingInput, parts[0] + '.' + parts[1]);
    assert.strictEqual(decoded.signatureB64u, parts[2]);
    assert.deepStrictEqual(decoded.payload, { sub: 'bob' });
    assert.strictEqual(decoded.header.alg, 'ES256K');
    assert.strictEqual(decoded.header.typ, 'JWT');
});

test('verifyJws rejects a JWS whose payload was tampered with', () => {
    const { issuer } = makeWorld();
    const jws = sdjwt.signJws({ sub: 'bob' }, issuer.sk);
    const [headerB64u, , signatureB64u] = jws.split('.');
    const tampered = headerB64u + '.' + b64uJson({ sub: 'mallory' }) + '.' + signatureB64u;

    const result = sdjwt.verifyJws(tampered, issuer.pk);
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /invalid JWS signature/i);
});

test('verifyJws rejects a JWS signed by a different key', () => {
    const attacker = keys.generateKeypair();
    const jws = sdjwt.signJws({ sub: 'bob' }, attacker.sk);
    const result = sdjwt.verifyJws(jws, keys.generateKeypair().pk);
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /invalid JWS signature/i);
});

test('verifyJws rejects malformed input instead of throwing', () => {
    const { issuer } = makeWorld();
    for (const bad of ['', 'not-a-jws', 'a.b', 'a.b.c.d', '.x.y']) {
        const result = sdjwt.verifyJws(bad, issuer.pk);
        assert.strictEqual(result.ok, false, 'expected rejection for ' + JSON.stringify(bad));
        assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
    }
});

// ---- disclosures ----

test('makeDisclosure produces a fresh salt and parseable [salt, name, value]', () => {
    const d1 = sdjwt.makeDisclosure('role', 'admin');
    const d2 = sdjwt.makeDisclosure('role', 'admin');
    assert.notStrictEqual(d1, d2, 'salts must be random');

    const parsed = sdjwt.parseDisclosure(d1);
    assert.strictEqual(parsed.length, 3);
    assert.strictEqual(typeof parsed[0], 'string');
    assert.strictEqual(base64urlDecode(parsed[0]).length, 16, 'salt must be 16 bytes');
    assert.strictEqual(parsed[1], 'role');
    assert.strictEqual(parsed[2], 'admin');
});

test('disclosureDigest is base64url(SHA-256(disclosure))', () => {
    const disclosure = sdjwt.makeDisclosure('amount', 42);
    const expected = base64url(createHash('sha256').update(disclosure, 'utf8').digest());
    assert.strictEqual(sdjwt.disclosureDigest(disclosure), expected);
});

// ---- issuance and presentation ----

test('issueSdJwt removes disclosable claims from the payload and commits digests', () => {
    const w = makeWorld();
    const decoded = sdjwt.decodeJws(w.issued.sdjwt);

    assert.strictEqual(decoded.payload._sd_alg, 'sha-256');
    assert.strictEqual(decoded.payload.vct, w.claims.vct);
    assert.strictEqual(decoded.payload.iss, w.claims.iss);
    assert.strictEqual('constraints' in decoded.payload, false, 'disclosable claim must be removed');
    assert.strictEqual('payment_amount' in decoded.payload, false, 'disclosable claim must be removed');

    assert.strictEqual(w.issued.disclosures.length, 2);
    assert.deepStrictEqual(
        decoded.payload._sd.slice().sort(),
        w.issued.disclosures.map(sdjwt.disclosureDigest).sort(),
    );
    assert.strictEqual(w.issued.digestByName.constraints, sdjwt.disclosureDigest(w.issued.disclosures[0]));
    assert.strictEqual(w.issued.digestByName.payment_amount, sdjwt.disclosureDigest(w.issued.disclosures[1]));
});

test('present/parsePresentation: trailing separator, with and without disclosures', () => {
    const w = makeWorld();
    const full = allDisclosures(w);
    assert.strictEqual(full, w.issued.sdjwt + '~' + w.issued.disclosures.join('~'));

    const parsedFull = sdjwt.parsePresentation(full);
    assert.strictEqual(parsedFull.jwt, w.issued.sdjwt);
    assert.deepStrictEqual(parsedFull.disclosures, w.issued.disclosures);

    const empty = sdjwt.present({ sdjwt: w.issued.sdjwt, disclosures: [] });
    assert.strictEqual(empty, w.issued.sdjwt + '~');
    assert.deepStrictEqual(sdjwt.parsePresentation(empty), { jwt: w.issued.sdjwt, disclosures: [] });
});

// ---- presentation verification: happy path ----

test('verifyPresentation merges all disclosures and keeps non-disclosable claims', () => {
    const w = makeWorld();
    const result = sdjwt.verifyPresentation({
        presentation: allDisclosures(w),
        issuerPubkey: w.issuer.pk,
        requiredClaims: ['vct', 'constraints', 'payment_amount'],
    });

    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.claims, w.claims);
    assert.deepStrictEqual(result.disclosed, {
        constraints: w.claims.constraints,
        payment_amount: w.claims.payment_amount,
    });
});

test('verifyPresentation allows a selective subset and leaves undisclosed claims absent', () => {
    const w = makeWorld();
    const presentation = sdjwt.present({
        sdjwt: w.issued.sdjwt,
        disclosures: [w.issued.disclosures[0]], // constraints only
    });

    const result = sdjwt.verifyPresentation({ presentation, issuerPubkey: w.issuer.pk });
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.claims.constraints, w.claims.constraints);
    assert.strictEqual('payment_amount' in result.claims, false);
    assert.deepStrictEqual(Object.keys(result.disclosed), ['constraints']);
});

// ---- presentation verification: rejections ----

test('verifyPresentation rejects an invalid issuer signature', () => {
    const w = makeWorld();
    const attacker = keys.generateKeypair();
    const forged = sdjwt.issueSdJwt({
        claims: { vct: w.claims.vct, iss: attacker.pk, constraints: { evil: true } },
        disclosable: ['constraints'],
        skHex: attacker.sk,
    });
    const presentation = sdjwt.present({ sdjwt: forged.sdjwt, disclosures: forged.disclosures });

    const result = sdjwt.verifyPresentation({ presentation, issuerPubkey: w.issuer.pk });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /invalid JWS signature/i);
});

test('verifyPresentation rejects _sd_alg other than sha-256', () => {
    const { issuer } = makeWorld();
    const jwt = sdjwt.signJws({ sub: 'x', _sd_alg: 'sha-512', _sd: [] }, issuer.sk);
    const result = sdjwt.verifyPresentation({
        presentation: jwt + '~',
        issuerPubkey: issuer.pk,
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /_sd_alg/);
});

test('verifyPresentation rejects a disclosure whose digest is not committed in _sd', () => {
    const w = makeWorld();
    const extra = sdjwt.makeDisclosure('admin', true);
    const presentation = sdjwt.present({
        sdjwt: w.issued.sdjwt,
        disclosures: w.issued.disclosures.concat(extra),
    });

    const result = sdjwt.verifyPresentation({ presentation, issuerPubkey: w.issuer.pk });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /not committed in _sd/i);
});

test('verifyPresentation rejects a duplicate disclosure', () => {
    const w = makeWorld();
    const duplicate = w.issued.disclosures[0];
    const presentation = sdjwt.present({
        sdjwt: w.issued.sdjwt,
        disclosures: [duplicate, duplicate],
    });

    const result = sdjwt.verifyPresentation({ presentation, issuerPubkey: w.issuer.pk });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /duplicate disclosure/i);
});

test('verifyPresentation rejects a disclosure overriding a non-disclosable claim', () => {
    const issuer = keys.generateKeypair();
    // An issuer that (buggily or maliciously) commits a disclosure for a claim
    // that is also present in the signed payload; verification must not let the
    // disclosure shadow the signed value.
    const colliding = sdjwt.makeDisclosure('iss', 'attacker-controlled');
    const jwt = sdjwt.signJws({
        iss: issuer.pk,
        _sd_alg: 'sha-256',
        _sd: [sdjwt.disclosureDigest(colliding)],
    }, issuer.sk);
    const presentation = jwt + '~' + colliding;

    const result = sdjwt.verifyPresentation({ presentation, issuerPubkey: issuer.pk });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /overrides non-disclosable claim/i);
});

test('verifyPresentation rejects missing requiredClaims', () => {
    const w = makeWorld();
    const presentation = sdjwt.present({
        sdjwt: w.issued.sdjwt,
        disclosures: [w.issued.disclosures[0]], // constraints only, payment_amount withheld
    });

    const result = sdjwt.verifyPresentation({
        presentation,
        issuerPubkey: w.issuer.pk,
        requiredClaims: ['constraints', 'payment_amount'],
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /missing required claims: payment_amount/);
});

test('verifyPresentation rejects a malformed presentation', () => {
    const { issuer } = makeWorld();
    for (const bad of ['', 'not-a-jws', undefined]) {
        const result = sdjwt.verifyPresentation({ presentation: bad, issuerPubkey: issuer.pk });
        assert.strictEqual(result.ok, false, 'expected rejection for ' + String(bad));
        assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
    }
});

// ---- key binding ----

test('buildKbJwt binds nonce, aud and sd_hash over the exact presentation', () => {
    const w = makeWorld();
    const presentation = allDisclosures(w);
    const kbJwt = sdjwt.buildKbJwt({
        presentation,
        nonce: 'nonce-123',
        aud: 'cp.example',
        holderSk: w.holder.sk,
        holderPk: w.holder.pk,
    });

    const verified = sdjwt.verifyKbJwt({
        kbJwt,
        presentation,
        nonce: 'nonce-123',
        aud: 'cp.example',
        holderPubkey: w.holder.pk,
    });
    assert.deepStrictEqual(verified, { ok: true });

    const payload = sdjwt.verifyJws(kbJwt, w.holder.pk).payload;
    assert.strictEqual(payload.nonce, 'nonce-123');
    assert.strictEqual(payload.aud, 'cp.example');
    assert.strictEqual(typeof payload.iat, 'number');
    assert.strictEqual(payload.sd_hash, sdHash(presentation));
});

test('verifyKbJwt rejects a wrong nonce', () => {
    const w = makeWorld();
    const presentation = allDisclosures(w);
    const kbJwt = sdjwt.buildKbJwt({
        presentation, nonce: 'nonce-123', aud: 'cp.example', holderSk: w.holder.sk,
    });
    const result = sdjwt.verifyKbJwt({
        kbJwt, presentation, nonce: 'nonce-456', aud: 'cp.example', holderPubkey: w.holder.pk,
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /nonce mismatch/i);
});

test('verifyKbJwt rejects a wrong audience', () => {
    const w = makeWorld();
    const presentation = allDisclosures(w);
    const kbJwt = sdjwt.buildKbJwt({
        presentation, nonce: 'nonce-123', aud: 'cp.example', holderSk: w.holder.sk,
    });
    const result = sdjwt.verifyKbJwt({
        kbJwt, presentation, nonce: 'nonce-123', aud: 'merchant.example', holderPubkey: w.holder.pk,
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /aud mismatch/i);
});

test('verifyKbJwt rejects a swapped presentation (sd_hash mismatch)', () => {
    const w = makeWorld();
    const presentation = allDisclosures(w);
    const otherPresentation = sdjwt.present({
        sdjwt: w.issued.sdjwt,
        disclosures: [w.issued.disclosures[0]],
    });
    const kbJwt = sdjwt.buildKbJwt({
        presentation, nonce: 'nonce-123', aud: 'cp.example', holderSk: w.holder.sk,
    });

    const result = sdjwt.verifyKbJwt({
        kbJwt,
        presentation: otherPresentation,
        nonce: 'nonce-123',
        aud: 'cp.example',
        holderPubkey: w.holder.pk,
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /sd_hash mismatch/i);
});

test('verifyKbJwt rejects a kb-jwt signed by a key other than the holder', () => {
    const w = makeWorld();
    const presentation = allDisclosures(w);
    const kbJwt = sdjwt.buildKbJwt({
        presentation, nonce: 'nonce-123', aud: 'cp.example', holderSk: keys.generateKeypair().sk,
    });
    const result = sdjwt.verifyKbJwt({
        kbJwt, presentation, nonce: 'nonce-123', aud: 'cp.example', holderPubkey: w.holder.pk,
    });
    assert.strictEqual(result.ok, false);
    assert.match(result.reason, /invalid JWS signature/i);
});
