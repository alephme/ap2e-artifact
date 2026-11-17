// 自包含的 Keccak-256 与最小 ABI 编码工具（纯 JS）。
// 替代 web3-utils/web3-eth-abi：我们只用到 bytes32、bytes32[2] 两种静态类型，
// 用 js-sha3 实现与 web3 字节级等价（由 test/compat.test.js 守护）。
// 这让运行时只需 bn.js / elliptic / js-sha3，不拖 web3 的重型传递依赖。
const BN = require('bn.js');
const { keccak256 } = require('js-sha3');

const strip0x = (hex) => (hex.startsWith('0x') ? hex.slice(2) : hex);

const hexToBytes = (hex) => {
  const clean = strip0x(hex);
  if (clean.length % 2 !== 0) throw new Error('odd-length hex: ' + hex);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
};

// keccak256(hex 字节) -> 64 字符 hex（无 0x 前缀）
function keccak256Hex(hex) {
  return keccak256(hexToBytes(hex));
}

const utf8ToHex = (str) =>
  Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

// 复刻 web3-utils soliditySha3 对"字符串 / 非负数字"的紧密打包：
//   string -> utf8 字节；number -> uint256（32 字节大端）
function soliditySha3Packed(...values) {
  const hex = values
    .map((v) => {
      if (typeof v === 'number') return new BN(v).toString('hex', 64);
      if (typeof v === 'string') return utf8ToHex(v);
      throw new Error('soliditySha3Packed: 不支持的值类型 ' + typeof v);
    })
    .join('');
  return '0x' + keccak256Hex(hex);
}

// 最小 ABI 编码（静态类型，等价于 web3-eth-abi encodeParameters 的输出）：
//   bytes32    -> 32 字节（64 hex）
//   bytes32[N] -> N 个 bytes32 顺序拼接
//   uint256    -> 32 字节大端
function abiEncode(types, values) {
  let out = '';
  for (let i = 0; i < types.length; i++) out += encodeStatic(types[i], values[i]);
  return '0x' + out;
}

function encodeStatic(type, value) {
  if (type === 'bytes32') return strip0x(value);
  if (type === 'uint256') return new BN(value).toString('hex', 64);
  const m = /^bytes32\[(\d+)\]$/.exec(type);
  if (m) {
    const n = parseInt(m[1], 10);
    if (value.length !== n) throw new Error(`abiEncode: ${type} 期望 ${n} 个元素`);
    return value.map(strip0x).join('');
  }
  throw new Error('abiEncode: 不支持的类型 ' + type);
}

module.exports = { keccak256Hex, soliditySha3Packed, abiEncode };
