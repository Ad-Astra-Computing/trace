# Cost / throughput report — v1.0.0 (Reviewer-LoRA corpus freeze)

**Scope**: every live Anthropic API invocation recorded under `traces/example/<bundle>/{patcher,reviewer,reproducer}-invocation.json`. Deterministic-stub runs (upstream-ref-resolver, Builder) are excluded.

**Generated**: 2026-06-17 (corpus-READY milestone; post-freeze). Counts reflect 162 live invocations across 67 bundles at git `06660b6d`.

**Canonical data layer**: [`data/reports/throughput-20260617T042654Z.{json,md}`](../data/reports/throughput-20260617T042654Z.md). That report defines "merge-ready" as `bundle.kind == "auto-merge"` (N=24 cert-green bundles). Sunk-cost bundles (retired, human-review-required, ASAN-path) are part of the total spend but excluded from the per-merge-ready figure.

---

## 1. Headline figures

| Metric | Value |
|---|---|
| Total live API spend (all roles, all bundles, including retired) | **$23.46** |
| Live invocations | 162 |
| Distinct bundles with any live invocation | 67 |
| Auto-merge cert-green bundles | 24 (cost data: $9.05 total) |
| **Cost per merge-ready bundle (mean, N=24)** | **$0.3772** |
| Human-review-required bundles | 42 |
| Source-backport validated | 15 |

**Comparison to v0.5.0 baseline** (N=3, $0.39/bundle, 2026-05-25): cost per merge-ready is stable across 8× more data points. The earlier estimate was not an outlier.

---

## 2. Per-role aggregates (all bundles)

| Role | n | Total $ | Mean $/call | In tokens | Out tokens |
|---|--:|--:|--:|--:|--:|
| patcher | 65 | $18.07 | $0.2779 | 281,945 | 92,777 |
| reviewer | 66 | $2.15 | $0.0326 | 307,853 | 35,944 |
| reproducer | 31 | $3.24 | $0.1046 | 122,368 | 50,087 |
| **total** | **162** | **$23.46** | — | 712,166 | 178,808 |

**Reading the role table.**

- Patcher (claude-opus-4-7/4-8, $15/M in + $75/M out) is the dominant cost: 77% of total spend. Output tokens are the cost driver — a 1,300-token patch costs ~$0.10 in output alone.
- Reviewer (claude-sonnet-4-5/4-6) is the cheapest role at $0.03/call. The Reviewer's output is short (accept/reject verdict + evidence citations); input is the bundle context, which is re-used from the Patcher's prefix.
- Reproducer (claude-sonnet-4-5-20250929) is moderate: $0.10/call. Only 31 of 67 bundles have a live Reproducer invocation; the rest refused (human-review-required shape) or predate the Reproducer role.

---

## 3. Scout throughput (candidate pipeline)

| Metric | Value |
|---|---|
| Cron runs | 449 |
| CVE advisories discovered (raw) | 10,797 |
| CVEs processed (deduped, schema-valid) | 7,452 |
| Eligible candidates (auto-merge path) | 87 |
| Eligible (human-review required) | 104 |
| Ineligible (no fix available) | 1,306 |
| Rate-limited fetches | 35 |

Eligible yield rate: ~1.6% of processed CVEs become candidates. The harvest is continuous; `eval/candidates.jsonl` is the live staging area.

---

## 4. Build time summary

Wall-clock total per-role (from `traces/example/*/replay.json` timings):

- Median bundle wall time (patcher + reviewer): ~47 s
- Median bundle wall time (patcher + reviewer + reproducer): ~74 s
- Outliers: CVE-2025-69194 (bzip2 reproducer, 303 s), CVE-2026-42250 (curl patcher, 342 s — 2-attempt retry)
- CI build time (patched nix-build, Linux cert): 5–25 min depending on binary cache hit rate

---

## 5. v0.5.0 → v1.0.0 cost trajectory

| Version | N | Mean $/bundle | Notes |
|---|---|---|---|
| v0 (2026-05-12) | 3 | $0.22 | Patcher + Reviewer only; no Reproducer |
| v0.5.0 (2026-05-25) | 3 | $0.39 | Full 3-role (Patcher + Reviewer + Reproducer) |
| **v1.0.0 (2026-06-17)** | **24** | **$0.3772** | 8× larger N; cost stable |

The $0.22 → $0.39 step was the Reproducer role addition (~$0.11/bundle). Since then, cost has been flat. At $0.38/bundle and a 50-bundle LoRA training corpus, total training-data acquisition cost is ~$19.

**Note on retry cost (added 27 July 2026):** every figure above, including the $0.3772/N=24 headline and the $0.22 v0 history entry, was measured before the Reviewer bounded auto-retry (`REVIEWER_MAX_ATTEMPTS=2`) landed. A bundle whose Reviewer retried once bills a second Reviewer call, so its per-bundle cost is correspondingly higher than these baselines suggest. `trace report throughput` now includes a "Reviewer retry summary" section that surfaces how many extra model calls a corpus incurred through retry.
