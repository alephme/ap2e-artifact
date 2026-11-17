// ECIES over BN128 + AES-256-GCM: round-trip, wrong-key rejection, tamper rejection.
const { test } = require('node:test');
const assert = require('node:assert');

const ecies = require('../src/crypto/ecies.js');

test('ecies round-trip', async () => {
  const kp = ecies.generateKeypair();
  const msg = 'hello 密封竞标 secret 你好 🎯';
  const envelope = await ecies.encrypt(kp.pk, msg);
  const decrypted = await ecies.decrypt(kp.sk, envelope);
  assert.strictEqual(decrypted, msg);
});

test('ecies decrypt with a different key throws', async () => {
  const kp1 = ecies.generateKeypair();
  const kp2 = ecies.generateKeypair();
  const envelope = await ecies.encrypt(kp1.pk, 'top secret');
  await assert.rejects(() => ecies.decrypt(kp2.sk, envelope), 'decrypt must throw on auth failure');
});

test('ecies tampered ciphertext throws', async () => {
  const kp = ecies.generateKeypair();
  const envelope = await ecies.encrypt(kp.pk, 'top secret');
  const tampered = { ...envelope };
  const ct = Buffer.from(tampered.ciphertextHex, 'hex');
  ct[0] ^= 0x01;
  tampered.ciphertextHex = ct.toString('hex');
  await assert.rejects(() => ecies.decrypt(kp.sk, tampered), 'decrypt must throw on tampered ciphertext');
});

test('ecies tampered tag throws', async () => {
  const kp = ecies.generateKeypair();
  const envelope = await ecies.encrypt(kp.pk, 'top secret');
  const tampered = { ...envelope };
  const tag = Buffer.from(tampered.tagHex, 'hex');
  tag[0] ^= 0x01;
  tampered.tagHex = tag.toString('hex');
  await assert.rejects(() => ecies.decrypt(kp.sk, tampered), 'decrypt must throw on tampered tag');
});
