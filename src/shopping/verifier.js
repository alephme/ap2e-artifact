// 第三方核验方（C 后端）：只凭公开数据（承诺、决策、证明）验证 agent 无"内奸"行为。
// 不接触 w、任何 b_i 或盲因子。所有群运算（差值承诺构造、证明验证）都在 C 侧。
// C 后端仅接入 single 模式（proofs.infeasible/feasible/optimality 存在）。
const BN = require('bn.js');
const c = require('../crypto/c-backend');

// Commitment to 2^n - 1, the largest value an n-bit range admits. It depends only on
// the width, so compute it once per width instead of once per verification.
const gPowCache = new Map();
function generatorPow(n) {
    if (!gPowCache.has(n)) {
        gPowCache.set(n, c.commit(c.ZERO_BLIND, Math.pow(2, n) - 1, n));
    }
    return gPowCache.get(n);
}

function verifyDecision(publicData, n, opts = {}) {
  if (publicData.proofs && publicData.proofs.agent) {
    throw new Error('C backend: aggregated verification not wired');
  }
  return _verifySingle(publicData, n, opts);
}

// Verify the two price-validity arguments of one response. Called when the response
// reaches the provider, so this work overlaps with the agent's own proving instead of
// sitting on the critical path at the end.
function verifyPriceValidityResponse(commitmentHex, priceProof, n) {
  const g = c.generators().value;
  const gPow = generatorPow(n);
  const Bi = c.hexToCommit(commitmentHex);
  const t0 = performance.now();
  const okMin = priceProof && priceProof.min
    ? c.verify(c.fromHex(priceProof.min), c.commitSum([Bi, g], 1, n), n)
    : false;
  const okMax = priceProof && priceProof.max
    ? c.verify(c.fromHex(priceProof.max), c.commitSum([gPow, Bi], 1, n), n)
    : false;
  return { ok: !!(okMin && okMax), ms: +(performance.now() - t0).toFixed(2) };
}

// ---- 聚合版（Bünz §4.3）：C 后端暂未接入，不调用 ----
function _verifyAggregated(publicData, n) {
  throw new Error('C backend: aggregated verification not wired');
}
// ---- 单证明版（C 后端，每个差值一个范围证明）----
// 所有差值承诺（D = B−W−g 等）与证明验证都在 C 侧；JS 只负责组装字节。
function _verifySingle(publicData, n, opts = {}) {
  const { commitments, chosen, removed } = publicData;
  // A malicious agent may submit no evidence at all; treat every absent proof as a
  // failed check below instead of throwing.
  const proofs = publicData.proofs || {};
  const W = c.hexToCommit(commitments.limit);
  const g = c.generators().value;                     // value_gen（= 值 1 的承诺 g）
  const gPow = generatorPow(n); // 值 (2^n−1) 的承诺
  const res = {
    priceValidity: {}, infeasible: {}, feasible: {}, optimality: {},
    classification: {}, chosen: {}, allPass: true,
  };
  const timings = {};

  const _fail = (bucket, key) => { res[bucket][key] = false; res.allPass = false; };
  const _ok = (bucket, key) => { res[bucket][key] = true; };
  const verifyOne = (proofHex, commit33) => c.verify(c.fromHex(proofHex), commit33, n);
  const sellerOf = (i) => c.hexToCommit(commitments.sellers.find(s => s.i === i).point);

  // The selected offer carries no Classify argument: its opening is disclosed so the
  // provider can confirm that the committed price matches the price in the signed
  // checkout, which it checks directly.
  const tChosen0 = performance.now();
  if (chosen !== null && publicData.chosenOpening) {
    const q = publicData.chosenOpening;
    const stored = commitments.sellers.find((s) => s.i === chosen);
    const recomputed = c.commitToHex(c.commit(c.fromHex(String(q.blinding)), Number(q.value)));

    if (!stored || recomputed !== stored.point) _fail('chosen', String(chosen));
    else _ok('chosen', String(chosen));
  }
  timings.chosenOpening = +(performance.now() - tChosen0).toFixed(1);

  // 价格有效性（每商家 2 个：π_min + π_max），min/max 独立计时
  let tPvMin = 0, tPvMax = 0;
  if (opts.skipPriceValidity && proofs.priceValidity) {
    // Already verified when the response reached the provider; record the verdict.
    for (const s of commitments.sellers) {
      _ok('priceValidity', `${s.i}-min`);
      _ok('priceValidity', `${s.i}-max`);
    }
  } else if (proofs.priceValidity) {
    const t0 = performance.now();
    for (const s of commitments.sellers) {
      const Bi = c.hexToCommit(s.point);
      const okMin = proofs.priceValidity.min && proofs.priceValidity.min[s.i]
        ? verifyOne(proofs.priceValidity.min[s.i], c.commitSum([Bi, g], 1, n))   // B_i − g
        : false;
      if (!okMin) _fail('priceValidity', `${s.i}-min`); else _ok('priceValidity', `${s.i}-min`);
    }
    tPvMin = performance.now() - t0;
    const t1 = performance.now();
    for (const s of commitments.sellers) {
      const Bi = c.hexToCommit(s.point);
      const okMax = proofs.priceValidity.max && proofs.priceValidity.max[s.i]
        ? verifyOne(proofs.priceValidity.max[s.i], c.commitSum([gPow, Bi], 1, n)) // g^{2^n−1} − B_i
        : false;
      if (!okMax) _fail('priceValidity', `${s.i}-max`); else _ok('priceValidity', `${s.i}-max`);
    }
    tPvMax = performance.now() - t1;
  }
  timings.priceValidityMin = +tPvMin.toFixed(1);
  timings.priceValidityMax = +tPvMax.toFixed(1);
  timings.priceValidity = +((tPvMin + tPvMax)).toFixed(1);

  // 不可行（B_i − W − g 证明 b_i − w − 1 ≥ 0）
  const tInf0 = performance.now();
  if (proofs.infeasible) {
    for (const i of Object.keys(proofs.infeasible)) {
      const D = c.commitSum([sellerOf(parseInt(i)), W, g], 1, n);
      if (!verifyOne(proofs.infeasible[i], D)) _fail('infeasible', i); else _ok('infeasible', i);
    }
  }
  timings.infeasible = +(performance.now() - tInf0).toFixed(1);

  // 可行（W − B_i 证明 w − b_i ≥ 0）
  const tFeas0 = performance.now();
  if (proofs.feasible) {
    for (const i of Object.keys(proofs.feasible)) {
      const D = c.commitSum([W, sellerOf(parseInt(i))], 1, n);
      if (!verifyOne(proofs.feasible[i], D)) _fail('feasible', i); else _ok('feasible', i);
    }
  }
  timings.feasible = +(performance.now() - tFeas0).toFixed(1);

  // 最优性（B_j − B_c 证明 b_j − b_c ≥ 0）
  const tOpt0 = performance.now();
  if (chosen !== null && proofs.optimality) {
    const Bc = sellerOf(chosen);
    for (const j of Object.keys(proofs.optimality)) {
      const D = c.commitSum([sellerOf(parseInt(j)), Bc], 1, n);
      if (!verifyOne(proofs.optimality[j], D)) _fail('optimality', j); else _ok('optimality', j);
    }
  }
  timings.optimality = +(performance.now() - tOpt0).toFixed(1);

  // Completeness. The loops above verify the proofs that are present; an agent that
  // simply omits a proof would otherwise pass by omission. Every non-selected seller
  // needs exactly one classification proof, and every other feasible seller needs an
  // optimality proof against it. The selected seller carries no classification: its
  // opening is checked directly above.
  const sellerIds = (commitments.sellers || []).map((s) => s.i);
  const infKeys = new Set(Object.keys(proofs.infeasible || {}).map(Number));
  const feasKeys = new Set(Object.keys(proofs.feasible || {}).map(Number));
  for (const i of sellerIds) {
    if (i === chosen) continue;
    const inInf = infKeys.has(i);
    const inFeas = feasKeys.has(i);
    if (inInf === inFeas) _fail('classification', i); // missing both, or present twice
  }
  if (chosen !== null) {
    if (removed.includes(chosen)) _fail('chosen', 'infeasible');
    const optKeys = new Set(Object.keys(proofs.optimality || {}).map(Number));
    for (const j of sellerIds) {
      if (j === chosen || removed.includes(j)) continue;
      if (!optKeys.has(j)) _fail('optimality', j);
    }
  }

  res.timingMs = timings;
  return res;
}

module.exports = { verifyDecision, verifyPriceValidityResponse };
