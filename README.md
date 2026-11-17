# AP2-E: Verifying Purchase Decisions in AP2 with Zero-Knowledge Proofs

This repository contains the prototype implementation and the experiment harness for
**AP2-E**, an extension of AP2 (the Agent Payments Protocol) that lets the credential
provider verify how a shopping agent obtained, compared, and selected an offer, without
learning the buyer's quote or the prices of non-selected offers.

AP2 authorises a purchase through signed mandates, but its checks do not establish that
the agent compared offers honestly or picked the best one. AP2-E adds three arguments on
top of the AP2 mandates:

* **quote consistency** — every registered merchant acknowledged the same inquiry price;
* **classification** — each offer is correctly labelled feasible or infeasible against the
  payment limit;
* **optimality** — the selected offer is the cheapest feasible one.

Merchants submit their signed responses directly to the credential provider (CP), so the
agent cannot drop or alter them, and the CP verifies range proofs over the committed
prices before issuing the payment credential.

This is an anonymous submission; author names and affiliations are omitted.

## Requirements

* Node.js >= 18 (all experiments were run with Node 20.18.1)
* npm

```bash
npm install
```

### Native proof backend

Pedersen commitments and Bulletproofs run in C (`libsecp256k1-zkp`) through
[`koffi`](https://www.npmjs.com/package/koffi). The Schnorr equality proofs for quote
consistency are pure JavaScript.

* **Windows**: prebuilt binaries are included in `src/crypto/lib/`
  (`bp_wrapper.dll` plus the MinGW runtime DLLs).
* **Linux / macOS**: build `bp_wrapper.so` from `scripts/c-backend/bp_wrapper.c`
  against a libsecp256k1-zkp checkout. The wrapper `#include`s the library's
  `src/secp256k1.c` directly, so no separate shared library is needed:

  ```bash
  gcc -O2 -shared -fPIC -I/path/to/secp256k1-zkp \
      -o src/crypto/lib/bp_wrapper.so scripts/c-backend/bp_wrapper.c
  ```

`ZKP_MODE=single` is the only mode wired to the C backend; the aggregated mode of an
earlier prototype is not connected and raises an error if selected.

## Quick start

```bash
npm test              # unit and integration tests (78 tests)
npm run start:all     # AP2 baseline and AP2-E, one merchant process each
```

`start:all` prints the demo pages:

| System | Agent | Page |
|---|---|---|
| AP2 baseline | <http://localhost:3201> | <http://localhost:3201/ap2-only.html> |
| AP2-E | <http://localhost:3301> | <http://localhost:3301/full.html> |

Both systems share one credential provider (`:3290`).

## Experiment harness

All experiment scripts live in `scripts/` and write JSON into `results/`. Every script
accepts `--seed` for reproducible scenario generation.

### 1. End-to-end latency and evidence size (Tables 1–2, Figure 7)

The benchmark runs one protocol execution per scenario and records both systems. Set the
two environment variables first:

```bash
export ZKP_MODE=single
export MAX_BODY_BYTES=67108864   # required at m=192; the default 1 MB limit is too small
```

One invocation collects every cell (7 merchant counts x 2 proof widths, 30 runs each)
and writes a single file:

```bash
node scripts/benchmark.js --groups 30 --merchants 4,8,16,32,64,128,192 --nbits 16,32 \
                          --seed 100 --output results/benchmark.json
```

`benchmark.js` flags: `--groups` (runs per cell), `--merchants`, `--nbits`, `--seed`,
`--output`, `--port-offset`, `--csv`.


Aggregate the single output file into the two datasets:

```bash
node scripts/build-dataset.js   # -> results/phase-time.json (runs: timing + evidence)
node scripts/build-evidence.js  # -> results/evidence.json  (runs: evidence only)
```

`scripts/ap2e-breakdown.js` re-computes the AP2-E time breakdown for a single cell:

```bash
node scripts/ap2e-breakdown.js --merchants 4 --nbits 32 --reps 30
```

### 2. Purchase-decision deviations (RQ1)

Four deviations are replayed against both systems (biased selection, offer exclusion,
quote equivocation, below-price rejection):

```bash
node scripts/ap2-deviations.js  --seed 42 --n 50      # AP2 baseline
node scripts/ap2e-deviations.js --seed 42 --reps 50   # AP2-E
node scripts/ap2-conformance.js --verbose             # artefact-level conformance check
```

Results are written to `results/rq1/`.

### 3. LLM-selected offers (Section 8)

A language model acts as the agent's decision maker: it is shown the plaintext offer
prices and the limit and names a merchant. The protocol code then runs unchanged, and the
purchase is authorised only if the selection is the cheapest feasible offer.

```bash
export DEEPSEEK_API_KEY=...        # deepseek-v4.1-flash
export OPENCODE_GO_API_KEY=...     # glm-5.3-flash, claude-haiku-5-5, gpt-6-luna

node scripts/llm-compat.js --personas honest,malicious --merchants 8 --seed 42
node scripts/llm-compat-full.js    # full per-model sweep
```

Personas change the instruction only; the protocol is identical. Results are written to
`results/llm/`.

## Measurement setup

The numbers in the paper come from the harness above and follow these conventions:

* **One host, no network.** All parties (agents, merchants, verifier, credential provider,
  payment processor) run on one AWS EC2 `i4i.large` instance (2 vCPU, Ubuntu 26.04,
  Node 20.18.1). Measured phases therefore contain no network latency; rows marked with an
  asterisk in the paper include one local HTTP round trip.
* **Merchant parallelism is modelled, not measured.** A single merchant process serves all
  `m` logical merchants, so the merchant block is the serial time of all `m` merchants.
  Per-merchant figures divide that block by `m`, which models merchants running on
  separate machines.
* **End-to-end is composed.** The reported end-to-end value is the folded merchant block
  plus the other phases as measured; it is not a single wall-clock measurement of a
  distributed purchase.
* **30 runs per cell** on one shared scenario set (`--seed 100`), reported as medians.
  A 95% confidence interval is obtained by bootstrapping the per-run values (2000
  resamples).
* **Evidence sizes are counted in binary.** Each range proof is 546 B (16-bit) or 610 B
  (32-bit), each consistency argument 96 B, each signature 86 B, and the mandate payloads
  are counted as serialized SD-JWT presentations. Transport encoding is excluded.

## Repository layout

```
src/
  crypto/        Pedersen commitments, Bulletproofs (C via koffi), Schnorr proofs,
                 ECIES, BN128 helpers; native binaries in crypto/lib/
  mandates/      AP2 mandate construction and SD-JWT handling
  shopping/      offer selection, commitment bookkeeping, verifier checks
  systems/       party servers: merchant, verifier (CP), credential provider, MPP,
                 plus the AP2 baseline agent and the AP2-E agent
  llm/           model adapter and decision bridge for Section 8
  web/           demo pages (ap2-only.html, full.html)
scripts/
  benchmark.js         latency and evidence-size benchmark (Tables 1–2)
  build-dataset.js     turn results/benchmark.json into results/phase-time.json
  build-evidence.js    extract the evidence-only dataset into results/evidence.json
  ap2e-breakdown.js    AP2-E phase breakdown for one cell
  ap2-deviations.js    AP2 half of the deviation experiments
  ap2e-deviations.js   AP2-E half of the deviation experiments
  ap2-conformance.js   artefact-level conformance check
  llm-compat.js        LLM compatibility experiment
  llm-compat-full.js   full per-model sweep
  build-browser.js     bundles the browser crypto demo
  launch-all.js        starts both demo systems
  c-backend/           C wrapper source for the native proof backend
results/
  phase-time.json      every run of the 14 cells (time + evidence)
  evidence.json        the same runs, evidence counts and bytes only
  llm/                 LLM experiment output
  rq1/                 deviation experiment output
test/                  node --test suites (crypto, SD-JWT, mandates, decisions, scenarios)
```

## Data flow

```
scripts/benchmark.js         -> results/benchmark.json        (every run of every cell)
scripts/build-dataset.js     -> results/phase-time.json        (all runs, one file)
scripts/build-evidence.js    -> results/evidence.json          (all runs, evidence only)
```

`phase-time.json` keeps the folded and raw end-to-end values (`e2eMs`, `e2eRawMs`), the
per-phase timings, and the proof counts and byte sizes, so the latency table, the evidence
table, and the scalability figure all read from the same file.

## Tests

```bash
npm test
```

The suite covers the Bulletproofs backend, SD-JWT handling, mandate construction, ECIES,
equality proofs, decision logic, and an end-to-end purchase in both systems.

## Scope and limitations

* The credential provider and the payment processor are local prototypes; no real payment
  network is contacted.
* Storage is in memory, and parties communicate over localhost HTTP without TLS.
* The proof backend is a research prototype: no proof batching, no distributed merchant
  deployment, and no side-channel hardening.
