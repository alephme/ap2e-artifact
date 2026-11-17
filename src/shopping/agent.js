// 买家 agent：生成密钥对、解密密封信封（仅 agent 可见明文）、决策、构建零知识证明。
// 所有"证明 agent 诚实"的职责都在这里；核验方见 verifier.js（只用公开数据）。
const BN = require('bn.js');
const bn128 = require('../crypto/bn128');
const ecies = require('../crypto/ecies');
const bulletproofs = require('../crypto/bulletproofs');
const { hexToPoint, parseOpening } = require('./commitments');

// ZKP_MODE: 'aggregated' (default, Bünz §4.3 single aggregated proof) or 'single'
// (one range proof per difference, the pre-aggregation baseline).
const ZKP_MODE = process.env.ZKP_MODE || 'aggregated';

class Agent {
  constructor({ sk, pk }) {
    this.sk = sk; // 私钥（red BN）
    this.pk = pk; // 公钥（点）
    this.quotes = []; // 每个卖家：{ valueInt, value, randomness, commitmentPoint }
    this.limit = null; // 用户上限：{ valueInt, value, randomness, commitmentPoint }
  }

  static generate() {
    const kp = ecies.generateKeypair();
    return new Agent(kp);
  }

  // 收到卖家 i 的密封信封（承诺公开，报价+盲因子加密给 agent）
  async receiveQuote(i, envelope) {
    const plain = await ecies.decrypt(this.sk, envelope.sealed);
    this.quotes[i] = {
      ...parseOpening(plain),
      commitmentPoint: hexToPoint(envelope.commitment),
    };
  }

  // 收到用户的密封上限信封
  async receiveLimit(envelope) {
    const plain = await ecies.decrypt(this.sk, envelope.sealed);
    this.limit = {
      ...parseOpening(plain),
      commitmentPoint: hexToPoint(envelope.commitment),
    };
  }

  // 决策：先剔除 b_i > w（严格大于，匹配论文 p_i > L），再从剩余中选最低价。并列最低任取其一。
  decide() {
    const removed = [];
    for (let i = 0; i < this.quotes.length; i++) {
      if (!this.quotes[i]) continue; // a rejection carries no offer
      if (this.quotes[i].valueInt > this.limit.valueInt) removed.push(i);
    }
    const remaining = [];
    for (let i = 0; i < this.quotes.length; i++) {
      if (!this.quotes[i]) continue;
      if (!removed.includes(i)) remaining.push(i);
    }
    let chosen = null;
    if (remaining.length > 0) {
      chosen = remaining.reduce((best, i) =>
        this.quotes[i].valueInt < this.quotes[best].valueInt ? i : best, remaining[0]);
    }
    return { removed, chosen, remaining };
  }

  // 构建零知识证明。
  //  → 分类（每笔报价恰好一个差值）：
  //    不可行（p_i > L）：Δ = B_i · W^{-1} · g^{-1} 打开到 d = p_i - L - 1 ∈ [0, 2^n)
  //    可行（p_i ≤ L）：  Δ = W · B_i^{-1} 打开到 d = L - p_i ∈ [0, 2^n)
  //  → 最优性（选中 c vs 其他可行报价 j）：Δ = B_j · B_c^{-1} 打开到 d = b_j - b_c ∈ [0, 2^n)
  // ZKP_MODE=aggregated：聚合成一个证明（Bünz §4.3），返回 { aggregatedProof, diffInfo }。
  // ZKP_MODE=single：每个差值一个证明，返回 { infeasibleProofs, feasibleProofs, optimalityProofs }。
  static _toRedInt(d) {
    return new BN(d).umod(bn128.curve.n).toRed(bn128.q);
  }

  buildProofs({ removed, chosen }, n) {
    if (ZKP_MODE === 'single') return this._buildProofsSingle(removed, chosen, n);
    return this._buildProofsAggregated(removed, chosen, n);
  }

  _buildProofsAggregated(removed, chosen, n) {
    const t0 = performance.now();
    const values = [];
    const blindings = [];
    const diffInfo = []; // [{ type: 'infeasible'|'feasible'|'optimality', index }]

    // 分类：每笔报价恰好一个差值（可行 or 不可行）
    for (let i = 0; i < this.quotes.length; i++) {
      if (removed.includes(i)) {
        const d = this.quotes[i].valueInt - this.limit.valueInt - 1;
        const rho = this.quotes[i].randomness.redSub(this.limit.randomness);
        values.push(Agent._toRedInt(d));
        blindings.push(rho);
        diffInfo.push({ type: 'infeasible', index: i });
      } else {
        const d = this.limit.valueInt - this.quotes[i].valueInt;
        const rho = this.limit.randomness.redSub(this.quotes[i].randomness);
        values.push(Agent._toRedInt(d));
        blindings.push(rho);
        diffInfo.push({ type: 'feasible', index: i });
      }
    }

    // 最优性：选中者 vs 其他可行报价
    if (chosen !== null) {
      const c = this.quotes[chosen];
      for (let j = 0; j < this.quotes.length; j++) {
        if (j === chosen || removed.includes(j)) continue;
        const d = this.quotes[j].valueInt - c.valueInt;
        const rho = this.quotes[j].randomness.redSub(c.randomness);
        values.push(Agent._toRedInt(d));
        blindings.push(rho);
        diffInfo.push({ type: 'optimality', index: j });
      }
    }

    const aggregatedProof = bulletproofs.proveRangeAggregated(values, blindings, n);
    const tProveMs = performance.now() - t0;

    return {
      aggregatedProof,
      diffInfo,
      timingMs: { prove: +tProveMs.toFixed(1) },
    };
  }

  _buildProofsSingle(removed, chosen, n) {
    const infeasibleProofs = {};
    const feasibleProofs = {};
    const optimalityProofs = {};

    // 分类（不可行 + 可行），每类独立累计计时
    let tInfeasibleMs = 0, tFeasibleMs = 0;
    for (let i = 0; i < this.quotes.length; i++) {
      const t0 = performance.now();
      if (removed.includes(i)) {
        const d = this.quotes[i].valueInt - this.limit.valueInt - 1;
        const rho = this.quotes[i].randomness.redSub(this.limit.randomness);
        infeasibleProofs[i] = bulletproofs.proveRange(Agent._toRedInt(d), rho, n);
        tInfeasibleMs += performance.now() - t0;
      } else {
        const d = this.limit.valueInt - this.quotes[i].valueInt;
        const rho = this.limit.randomness.redSub(this.quotes[i].randomness);
        feasibleProofs[i] = bulletproofs.proveRange(Agent._toRedInt(d), rho, n);
        tFeasibleMs += performance.now() - t0;
      }
    }

    // 最优性
    const tOpt0 = performance.now();
    if (chosen !== null) {
      const c = this.quotes[chosen];
      for (let j = 0; j < this.quotes.length; j++) {
        if (j === chosen || removed.includes(j)) continue;
        const d = this.quotes[j].valueInt - c.valueInt;
        const rho = this.quotes[j].randomness.redSub(c.randomness);
        optimalityProofs[j] = bulletproofs.proveRange(Agent._toRedInt(d), rho, n);
      }
    }
    const tOptimalityMs = performance.now() - tOpt0;

    const total = tInfeasibleMs + tFeasibleMs + tOptimalityMs;
    return {
      infeasibleProofs, feasibleProofs, optimalityProofs,
      timingMs: {
        infeasible: +tInfeasibleMs.toFixed(1),
        feasible: +tFeasibleMs.toFixed(1),
        optimality: +tOptimalityMs.toFixed(1),
        prove: +total.toFixed(1),
      },
    };
  }
}

module.exports = Agent;
