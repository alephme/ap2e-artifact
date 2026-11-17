# C 后端原型（feature/c-backend 分支）

探索：在 JS 里调用 secp256k1-zkp（Andrew Poelstra / Blockstream Elements 的
libsecp256k1 fork）编译的 C Bulletproofs，评估性能与接入成本。

## 重要更正（2026-08-17）

secp256k1-zkp 仓库**主分支**（secp256k1-mw，HEAD 7dd7883）的
`ENABLE_MODULE_RANGEPROOF` 是 **Borromean 环签名范围证明**（2015 年 Gregory
Maxwell 的旧方案，证明 ~5KB），**不是 Bulletproofs**。

真正的 Bulletproofs 实现在**另一分支** `origin/bulletproofs`（08a0f91，
Poelstra 2020 年实现，含 rangeproof_impl.h / inner_product_impl.h /
circuit 支持，未合入主线）。本目录的 DLL 基于该分支编译。

## 产物（全部 MinGW x86_64 编译）

| 文件 | 说明 |
|---|---|
| `lib/libsecp256k1_bp.dll` | 真 Bulletproofs DLL（195 KB，`-DENABLE_MODULE_BULLETPROOF` 等宏）|
| `lib/bp_wrapper.dll` | 薄 C 封装（49 KB）：把复杂 API 简化为单值 `bp_init/commit/prove/verify` |
| `lib/libgcc_s_seh-1.dll` 等 | MinGW 运行时依赖 |
| `bp.js` | koffi 调用演示 + 性能基准 |
| `test_bp.c` | C 侧自洽测试（prove/verify）|

## 编译命令（在 secp256k1-zkp 的 local-bulletproofs 分支）

```bash
gcc -O2 -m64 -std=gnu89 -I. -Isrc -Iinclude \
  -DHAVE___INT128 \
  -DENABLE_MODULE_GENERATOR -DENABLE_MODULE_COMMITMENT -DENABLE_MODULE_BULLETPROOF -DENABLE_MODULE_ECDH \
  -DUSE_NUM_NONE -DUSE_FIELD_INV_BUILTIN -DUSE_SCALAR_INV_BUILTIN \
  -DUSE_FIELD_5X52 -DUSE_ASM_X86_64 -DUSE_SCALAR_4X64 \
  -shared -o libsecp256k1_bp.dll src/secp256k1.c
gcc -O2 -m64 -I. -Isrc -Iinclude -DHAVE___INT128 <同宏> \
  -shared -o bp_wrapper.dll bp_wrapper.c -L. -l:libsecp256k1_bp.dll
```

## 性能（n=32，本地 i5-1340P，中位数/20 次）

| | C Bulletproofs | JS 版 | 论文 Table 2 |
|---|---|---|---|
| prove | 6.49 ms | ~650 ms | 15 ms（2.0GHz）|
| verify | 0.85 ms | ~323 ms | 2.4 ms |
| 证明大小 | **610 B** | ~1.1 KB | **610 B** |

prove 快 ~100×，verify 快 ~380×，证明大小与论文 32-bit 值完全一致。

## 语义差异（接入前须知）

- 这是 Elements 工程版 Bulletproofs：API 是 `secp256k1_bulletproof_rangeproof_prove/verify`，
  支持聚合（n_commits）与 circuit；验证基于承诺 + 生成元向量，**不是** demo 里
  verifier.js 手写的原版验证方程（虽然底层算法相同）。
- 曲线是 **secp256k1**（demo 有 `ZKP_CURVE=secp256k1` 开关），切 C 后端意味着
  全部承诺/证明换曲线、数据重跑。
- `bp_wrapper.c` 用固定 nonce 派生盲因子（演示）；生产接入需改为每次随机并支持
  rewind。

## 接入状态

- [x] DLL 编译（MinGW）
- [x] JS→C 调用（koffi）prove/verify 打通
- [x] 性能/证明大小验证（610 B，6.5/0.85 ms）
- [ ] 接入 zkp-demo 密码学层（承诺、verifier、序列化、single 模式全链路）
- [ ] 数据重跑（secp256k1 曲线）
