// 薄封装：直接 include secp256k1.c（完整库实现 + Bulletproofs 模块），
// 再包一层简单接口供 koffi 调用。产出独立 DLL（不依赖 libsecp256k1_bp.dll）。
// 原则：所有群运算（承诺、差值承诺、证明、验证）都在 C 侧；JS 只传字节。
#include <stdint.h>
#include <stddef.h>

#include "src/secp256k1.c"

static secp256k1_context* g_ctx = NULL;
static secp256k1_generator g_value_gen, g_blind_gen;
static secp256k1_bulletproof_generators* g_gens = NULL;
static secp256k1_scratch_space* g_scratch = NULL;
static size_t g_nbits = 0;

/* 只初始化上下文 + 两个基础生成元（commit/commit_sum 只需要这些，不建证明用生成元组） */
static int ensure_basic_ctx(void) {
    if (g_ctx) return 1;
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!g_ctx) return 0;
    unsigned char s1[32] = {1}, s2[32] = {2};
    secp256k1_generator_generate(g_ctx, &g_value_gen, s1);
    secp256k1_generator_generate(g_ctx, &g_blind_gen, s2);
    g_nbits = 0;
    return 1;
}

int bp_init(size_t nbits) {
    if (g_ctx && g_nbits == nbits) return 1;
    if (!ensure_basic_ctx()) return 0;
    g_nbits = nbits;
    if (g_gens) secp256k1_bulletproof_generators_destroy(g_ctx, g_gens);
    if (g_scratch) secp256k1_scratch_space_destroy(g_scratch);
    g_gens = secp256k1_bulletproof_generators_create(g_ctx, &g_blind_gen, 2 * nbits);
    g_scratch = secp256k1_scratch_space_create(g_ctx, 1u << 22);
    return (g_gens && g_scratch) ? 1 : 0;
}

/* 承诺：blind(32B) + value → 33B 承诺（压缩）。不触发 gens/scratch 重建。 */
int bp_commit(const unsigned char* blind, uint64_t value, unsigned char* commit_out) {
    if (!ensure_basic_ctx()) return 0;
    return secp256k1_pedersen_commit(g_ctx, (secp256k1_pedersen_commitment*)commit_out,
                                     blind, value, &g_value_gen, &g_blind_gen);
}

/* 承诺求和/差：commits_in 为 n 个连续 33B 承诺，前 npos 个为正、其余为负，结果 out33 */
int bp_commit_sum(const unsigned char* commits_in, size_t n, size_t npos, unsigned char* out33) {
    if (n == 0 || npos > n) return 0;
    secp256k1_gej sumj;
    secp256k1_gej_set_infinity(&sumj);
    size_t i;
    for (i = 0; i < n; i++) {
        secp256k1_ge ge;
        secp256k1_pedersen_commitment_load(&ge, (const secp256k1_pedersen_commitment*)&commits_in[i * 33]);
        if (i >= npos) secp256k1_ge_neg(&ge, &ge);
        secp256k1_gej_add_ge(&sumj, &sumj, &ge);
    }
    secp256k1_ge outge;
    secp256k1_ge_set_gej(&outge, &sumj);
    secp256k1_pedersen_commitment_save((secp256k1_pedersen_commitment*)out33, &outge);
    return 1;
}

/* 盲因子求和/差：blinds_flat 为 n 个连续 32B 盲因子，前 npos 正、其余负，结果 out32 */
int bp_blind_sum_flat(unsigned char* blind_out, const unsigned char* blinds_flat, size_t n, size_t npos) {
    if (!g_ctx || n == 0 || n > 64 || npos > n) return 0;
    const unsigned char* ptrs[64];
    size_t i;
    for (i = 0; i < n; i++) ptrs[i] = blinds_flat + i * 32;
    return secp256k1_pedersen_blind_sum(g_ctx, blind_out, ptrs, n, npos);
}

/* 范围证明：value + blind → proof（plen in/out） */
int bp_prove(unsigned char* proof, size_t* plen, uint64_t value,
             const unsigned char* blind, size_t nbits) {
    if (!g_ctx || g_nbits != nbits) { if (!bp_init(nbits)) return 0; }
    uint64_t minv = 0;
    const unsigned char* blinds[1] = { blind };
    unsigned char nonce[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    return secp256k1_bulletproof_rangeproof_prove(g_ctx, g_scratch, g_gens, proof, plen,
        &value, &minv, blinds, 1, &g_value_gen, nbits, nonce, NULL, 0);
}

/* 验证：proof + 33B 承诺，证明其值 ∈ [0, 2^nbits) */
int bp_verify(const unsigned char* proof, size_t plen, const unsigned char* commit, size_t nbits) {
    if (!g_ctx || g_nbits != nbits) { if (!bp_init(nbits)) return 0; }
    uint64_t minv = 0;
    return secp256k1_bulletproof_rangeproof_verify(g_ctx, g_scratch, g_gens, proof, plen,
        &minv, (const secp256k1_pedersen_commitment*)commit, 1, nbits, &g_value_gen, NULL, 0);
}

/* 生成元导出（33B 压缩） */
int bp_generator_value(unsigned char* out33) {
    if (!g_ctx) return 0;
    return secp256k1_generator_serialize(g_ctx, out33, &g_value_gen);
}
int bp_generator_blind(unsigned char* out33) {
    if (!g_ctx) return 0;
    return secp256k1_generator_serialize(g_ctx, out33, &g_blind_gen);
}
