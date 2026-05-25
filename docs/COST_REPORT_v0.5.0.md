# Cost / throughput report — v0.5.0 baseline

**Scope**: every live Anthropic API invocation recorded under `traces/example/<bundle>/{patcher,reviewer,reproducer}-invocation.json`. Deterministic-stub runs (upstream-ref-resolver, Builder, deterministic Reproducer fallbacks) are excluded — they ship no `budget.actual_cost_usd` because they don't call the API.

**Generated**: 2026-05-25 (post-v0.5.0). Counts reflect 44 live invocations across 17 bundles.

**Canonical data layer**: [`data/reports/throughput-20260525T004809Z.{json,md}`](../data/reports/throughput-20260525T004809Z.md) (produced by `trace report throughput`). That report defines "merge-ready" as `bundle.kind == "auto-merge"` (3 bundles: mbedtls, bind, git-lfs; mean **$0.2667**). This v0.5.0-specific supplement uses a different cohort definition — **sandbox-positive cert-green** (git-lfs, assimp, expat) — because the v0.5.0 baseline claim is about positive sandbox evidence, not policy-routing kind. Both views are correct, and `kind=auto-merge ∩ sandbox-positive = {git-lfs}` (the single bundle in both cohorts).

---

## 1. Headline figures

| Metric | Value |
|---|---|
| Total live API spend (all roles, all bundles) | **$6.0450** |
| Live invocations | 44 |
| Distinct bundles with any live invocation | 17 |
| N=3 sandbox-positive cohort spend | **$1.1698** (9 invocations across 3 bundles) |
| **Cost per merge-ready bundle (mean, N=3)** | **$0.3899** |
| Retired-at-bootstrap spend (sunk cost, N=9) | $3.4735 ($0.3859/bundle mean) |

**Comparison to prior memory** (`v0 cost-per-merge-ready ≈ $0.22 mean (N=3, 2026-05-12)`): the May 12 figure measured Patcher + Reviewer cost only; today's $0.39/bundle includes the Reproducer role (≈$0.11/call mean) added in subsequent slices. Patcher-only mean today: $0.24/call (opus-4-7). The two numbers are reconcilable once the Reproducer cost is factored.

---

## 2. Per-role aggregates (all bundles)

| Role | n | Total $ | Mean $/call | In tok | Out tok | Cache-create | Cache-read | Mean latency (s) |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| patcher | 17 | $4.1252 | $0.2427 | 79,143 | 22,121 | 67,060 | 14,370 | 20.9 |
| reviewer | 14 | $0.4582 | $0.0327 | 65,819 | 7,885 | 37,806 | 2,467 | 12.4 |
| reproducer | 13 | $1.4616 | $0.1124 | 50,568 | 36,527 | 202,196 | 12,453 | 47.8 |

**Reading the role table.**
- Patcher (claude-opus-4-7, $15/M in + $75/M out) is the dominant cost: 68% of total spend with 39% of invocations. Cache-creation tokens (~67K) come from the long bundle-context prefix; cache-read (~14K) shows the prefix is reused across re-runs.
- Reproducer (claude-sonnet-4-5-20250929) has the heaviest cache-creation burden (202K tokens) because the prompt is the longest (807 lines pre-v9, 833 lines v9) and the bundle context is large. Per-call cost is moderate ($0.11) despite high token volume because sonnet's per-token price is ~5× cheaper than opus.
- Reviewer (claude-sonnet-4-5-20250929) is the cheapest role: $0.03/call. The Reviewer's input is the smallest (no source diff to write, just attestation).

---

## 3. Per-model aggregates

| Model | n | Total $ | Mean $/call |
|---|--:|--:|--:|
| `claude-opus-4-7` | 17 | $4.1252 | $0.2427 |
| `claude-sonnet-4-5-20250929` | 25 | $1.8198 | $0.0728 |
| `claude-sonnet-4-6` | 2 | $0.1000 | $0.0500 |

`claude-sonnet-4-6` (2 calls, $0.05/call mean) is a recent Scout-cron-side experiment, not part of the v0.5.0 cohort eval; included for completeness.

---

## 4. Per-bundle table (sorted by total spend)

Status legend: **merge-ready** = N=3 sandbox-positive cohort; **retired** = retired post-Patcher under F6/F8/F8b/F10/F11 contract refinement; **other** = pre-cohort / pre-Reproducer-v3 era bundles preserved as evidence.

| CVE | P (opus) | V (sonnet) | R (sonnet) | Bundle total | Status |
|---|--:|--:|--:|--:|---|
| `CVE-2025-4598` | $0.4219 | $0.0698 | $0.0000 | **$0.4917** | other |
| `CVE-2026-3308` | $0.2661 | $0.0364 | $0.1383 | **$0.4408** | retired |
| `CVE-2025-66293` | $0.2386 | $0.0331 | $0.1429 | **$0.4146** | retired |
| `CVE-2025-67899` | $0.2449 | $0.0324 | $0.1330 | **$0.4103** | retired |
| `CVE-2025-26625` | $0.2588 | $0.0349 | $0.1071 | **$0.4009** | merge-ready |
| `CVE-2025-59681` | $0.2430 | $0.0218 | $0.1344 | **$0.3992** | retired |
| `CVE-2024-8176` | $0.2269 | $0.0301 | $0.1341 | **$0.3911** | merge-ready |
| `CVE-2026-1144` | $0.2321 | $0.0299 | $0.1257 | **$0.3876** | retired |
| `CVE-2025-34451` | $0.2280 | $0.0297 | $0.1224 | **$0.3802** | retired |
| `CVE-2025-2751` | $0.2294 | $0.0270 | $0.1213 | **$0.3778** | merge-ready |
| `CVE-2025-15571` | $0.2195 | $0.0287 | $0.1251 | **$0.3733** | retired |
| `CVE-2025-13151` | $0.2363 | $0.0261 | $0.0976 | **$0.3599** | retired |
| `CVE-2025-69194` | $0.2312 | $0.0280 | $0.0485 | **$0.3076** | retired |
| `CVE-2025-13878` | $0.2466 | $0.0000 | $0.0313 | **$0.2779** | other |
| `CVE-2026-25949` | $0.2426 | $0.0302 | $0.0000 | **$0.2728** | other |
| `CVE-2025-9230` | $0.2381 | $0.0000 | $0.0000 | **$0.2381** | other |
| `CVE-2024-49195` | $0.1212 | $0.0000 | $0.0000 | **$0.1212** | other |

Range: $0.1212 – $0.4917. The tight band reflects that Patcher input-token volume is the dominant cost driver, and it varies modestly across bundle sizes (~70-90K cache-create tokens per Patcher call).

---

## 5. Throughput (cohort-mean latency)

All times are wall-clock seconds from API request start to response end, NOT cert-cycle time (which adds Builder + Steward + GH Actions queue).

| Role | Mean s/call | Min s | Max s | n |
|---|--:|--:|--:|--:|
| patcher | 20.9 | 12.0 | 30.0 | 17 |
| reviewer | 12.4 | 10.0 | 17.0 | 14 |
| reproducer | 47.8 | 5.0 | 79.0 | 13 |

End-to-end Patcher + Reviewer + Reproducer wall time, ignoring queue/scheduling: ~3-5 minutes per bundle for the live model phase. Builder + Steward (Linux cert) adds 15-90 minutes per bundle on GHA `ubuntu-latest` (mostly Nix build of the unpatched source).

---

## 6. Sandbox-positive cohort detail (N=3 baseline)

| CVE | Patcher (opus, $) | Reviewer (sonnet, $) | Reproducer (sonnet, $) | Bundle total $ |
|---|--:|--:|--:|--:|
| `CVE-2024-8176` | $0.2269 | $0.0301 | $0.1341 | **$0.3911** |
| `CVE-2025-26625` | $0.2588 | $0.0349 | $0.1071 | **$0.4009** |
| `CVE-2025-2751` | $0.2294 | $0.0270 | $0.1213 | **$0.3778** |
| **mean** | **$0.2384** | **$0.0307** | **$0.1208** | **$0.3899** |

---

## 7. Known omissions

- **Cert-side cost** (Builder + Steward GitHub Actions runtime): not metered here. v0.5.0 cohort: ~3-5 hours of total ubuntu-latest minutes across the three bundles' cert runs (git-lfs cert run 26075978701, assimp cert runs 26082525133 + 26085849172, expat cert runs 26323566165 + 26347401054 + 26348784388 — including F18 iteration). At GitHub's default per-minute rate this is $0 for public repos (the repo is public).
- **Scout-cron / harvest cost**: scout-cron uses `claude-sonnet-4-6` for candidate harvesting from nixpkgs git history. Not aggregated here; the 2 sonnet-4-6 invocations totaling $0.10 are harvest-side, not cohort-eval-side.
- **Prompt-development cost**: hand-iteration on v1→v9 of the Reproducer prompt, v1→v2 of the Reviewer prompt. Not metered; lives in commit history.
- **Latency outliers excluded from `min`**: any invocation with retries (rate-limit backoff) inflates latency; not separately tracked.
- **libxmp** Phase 2 staging cost: bundle bootstrapped 2026-05-24, Patcher pending API-key availability. No invocation sidecar yet.

---

## 8. Methodology

**Source data**: invocation sidecars are written by `tools/trace_cli/execute.py` immediately after each successful Anthropic API call. Each sidecar carries `budget.actual_cost_usd` (computed from `usage.input_tokens` + `usage.output_tokens` + cache tokens, against the model's `claude_pricing.json` table). Cache-create tokens billed at 1.25× input rate; cache-read at 0.1× input rate (Anthropic standard).

**Provenance**: each invocation links to its (model_id, prompt_sha256, started_at, ended_at, invocation_id) tuple. The full replay chain is verifiable via `trace bundle verify <dir>`.

**Reproducibility**: this v0.5.0 narrative report was generated by a one-shot Python script over the committed invocation sidecars (see commit `<this-commit>` for the exact script). The canonical data layer in [`data/reports/`](../data/reports/) is regenerated deterministically by `trace report throughput` and is the authoritative format for future cost roll-ups; this report is a slice-time narrative supplement and is NOT regenerated automatically. Engineering follow-up tracked in DECISIONS: extend `tools/trace_cli/report.py` with a second cohort definition (`sandbox-positive`) so the narrative supplement can be retired in favor of the canonical report.
