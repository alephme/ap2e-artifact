// 兼容性守护：自实现的 keccak256Hex / soliditySha3Packed / abiEncode 必须与
// web3-utils / web3-eth-abi 的输出字节级一致，保证与 zether 链上方案完全同构。
// （web3 仅为 devDependency，仅在本测试中使用。）
const test = require('node:test');
const assert = require('node:assert/strict');
const { soliditySha3, sha3 } = require('web3-utils');
const ABICoder = require('web3-eth-abi');

const { keccak256Hex, soliditySha3Packed, abiEncode } = require('../src/crypto/keccak.js');
const bn128 = require('../src/crypto/bn128.js');
const params = require('../src/crypto/params.js');
const utils = require('../src/crypto/utils.js');

const strip0x = (h) => (h.startsWith('0x') ? h.slice(2) : h);

test('keccak256Hex 与 web3 sha3 一致（含空输入已知向量）', () => {
  // 以太坊 keccak256('') 的已知值
  assert.equal(keccak256Hex(''), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(keccak256Hex('47'), strip0x(sha3('0x47')));
});

test('soliditySha3Packed 与 soliditySha3 对生成元种子字节级一致', () => {
  for (const seed of ['G', 'H']) {
    assert.equal(soliditySha3Packed(seed), soliditySha3(seed), `soliditySha3Packed("${seed}")`);
    for (let i = 0; i < 64; i++) {
      assert.equal(soliditySha3Packed(seed, i), soliditySha3(seed, i), `soliditySha3Packed("${seed}", ${i})`);
    }
  }
});

test('生成元锚点与 Solidity 常量一致（经由自实现哈希）', () => {
  const xy = (pt) => [pt.getX().toString(16, 64), pt.getY().toString(16, 64)];
  assert.deepEqual(xy(params.g), [
    '077da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4',
    '01485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875',
  ]);
  assert.deepEqual(xy(params.gs.getVector()[0]), [
    '0d1fff31f8dfb29333568b00628a0f92a752e8dee420dfede1be731810a807b9',
    '06c3001c74387dae9deddc75b76959ef5f98f1be48b0d9fc8ff6d7d76106b41b',
  ]);
  assert.deepEqual(xy(params.hs.getVector()[0]), [
    '01d39aef1308fae84642befcdb6c07f655cc4d092f6a66f464cb9c959bff743a',
    '277420423ebed18174bd2730d4387b06c10958e564af6444333ac5b30767c59c',
  ]);
  assert.deepEqual(xy(params.gSum), [
    '2257118d30fe5064dda298b2fac15cf96fd51f0e7e3df342d0aed40b8d7bb151',
    '0d4250e7509c99370e6b15ebfe4f1aa5e65a691133357901aa4b0641f96c80a8',
  ]);
});

test('abiEncode + utils.hash 与 web3 encodeParameters + soliditySha3 一致', () => {
  // 构造一组代表性输入（bytes32、bytes32[2] 的组合）
  const byt = (i) => bn128.bytes(new (require('bn.js'))(i).toRed(bn128.q));
  const ser = (seed) => [byt(123), byt(seed)];
  const cases = [
    { types: ['bytes32[2]', 'bytes32[2]', 'bytes32[2]'], values: [ser(1), ser(2), ser(3)] },
    { types: ['bytes32', 'bytes32[2]', 'bytes32[2]'], values: [byt(9), ser(4), ser(5)] },
    { types: ['bytes32', 'bytes32', 'bytes32'], values: [byt(7), byt(8), byt(9)] },
    { types: ['bytes32'], values: [byt(42)] },
  ];
  for (const c of cases) {
    const mine = abiEncode(c.types, c.values);
    const theirs = ABICoder.encodeParameters(c.types, c.values);
    assert.equal(mine, theirs, `abiEncode 与 encodeParameters 不一致: ${JSON.stringify(c.types)}`);
    // utils.hash 也一致（keccak256(abi.encode) mod q；两侧都做模 q 归约）
    assert.equal(
      utils.hash(mine).fromRed().toString(16),
      new (require('bn.js'))(soliditySha3(theirs).slice(2), 16).umod(bn128.curve.n).toString(16),
    );
  }
});
