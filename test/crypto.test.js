// Low-level crypto primitives: params anchors, mapInto, serialize/deserialize, red-BN arithmetic.
const { test } = require('node:test');
const assert = require('node:assert');
const BN = require('bn.js');
const { soliditySha3 } = require('web3-utils');

const bn128 = require('../src/crypto/bn128.js');
const utils = require('../src/crypto/utils.js');
const params = require('../src/crypto/params.js');

const pointHex = (p) => [p.getX().toString(16, 64), p.getY().toString(16, 64)];

test('params anchors: g, gs[0], hs[0], gSum match Solidity verifiers', () => {
  assert.deepStrictEqual(pointHex(params.g), [
    '077da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4',
    '01485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875',
  ]);
  assert.deepStrictEqual(pointHex(params.gs.getVector()[0]), [
    '0d1fff31f8dfb29333568b00628a0f92a752e8dee420dfede1be731810a807b9',
    '06c3001c74387dae9deddc75b76959ef5f98f1be48b0d9fc8ff6d7d76106b41b',
  ]);
  assert.deepStrictEqual(pointHex(params.hs.getVector()[0]), [
    '01d39aef1308fae84642befcdb6c07f655cc4d092f6a66f464cb9c959bff743a',
    '277420423ebed18174bd2730d4387b06c10958e564af6444333ac5b30767c59c',
  ]);
  assert.deepStrictEqual(pointHex(params.gSum), [
    '2257118d30fe5064dda298b2fac15cf96fd51f0e7e3df342d0aed40b8d7bb151',
    '0d4250e7509c99370e6b15ebfe4f1aa5e65a691133357901aa4b0641f96c80a8',
  ]);
});

test('g also equals the curve generator', () => {
  assert.ok(params.g.eq(bn128.curve.g));
});

test('mapInto is deterministic (same input -> same point)', () => {
  const seed = soliditySha3('determinism-test');
  const p1 = utils.mapInto(seed);
  const p2 = utils.mapInto(seed);
  assert.ok(p1.eq(p2));
});

test('serialize/deserialize round-trip for a random point and bn128.zero', () => {
  const rp = bn128.curve.g.mul(bn128.randomScalar());
  const [x, y] = bn128.serialize(rp);
  assert.ok(bn128.deserialize([x, y]).eq(rp));

  const [zx, zy] = bn128.serialize(bn128.zero);
  assert.ok(bn128.deserialize([zx, zy]).eq(bn128.zero));
});

test('red-BN arithmetic smoke: add, mul, inverse', () => {
  const a = bn128.randomScalar();
  const b = bn128.randomScalar();
  const one = new BN(1).toRed(bn128.q);
  if (a.isZero()) { assert.ok(a.isZero()); return; } // vanishingly unlikely
  assert.ok(a.redAdd(b).redSub(a).eq(b), 'a + b - a == b');
  assert.ok(a.redMul(b).redMul(a.redInvm()).eq(b), 'a * b * a^-1 == b');
  assert.ok(a.redInvm().redMul(a).eq(one), 'a^-1 * a == 1');
});
