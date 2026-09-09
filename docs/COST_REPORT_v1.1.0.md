# Cost and throughput report, v1.1.0

**Generated**: 2026-09-09 at git `fc5bf229`. Supersedes [COST_REPORT_v1.0.0.md](COST_REPORT_v1.0.0.md)
(2026-06-17), which remains accurate for the corpus freeze it describes.

**Scope**: every live Anthropic API invocation recorded in a
`{patcher,reviewer,reproducer}-invocation.json` sidecar under `traces/`. Deterministic roles
(upstream-ref-resolver, Builder, Steward) make no model call and cost nothing. Section 5 lists
the spend that exists but is not instrumented, which is the part of this report to read first if
you are deciding whether to trust the totals.

**Canonical data layer**:
[`data/reports/throughput-20260909T031437Z.{json,md}`](../data/reports/throughput-20260909T031437Z.md),
written by `trace report throughput`. That report scopes to `traces/example`; the tables below
that say "all lanes" additionally count `traces/negatives`, `traces/positives-reorg` and the
adaptation eval lane, which is where the difference between $40.45 and $73.39 comes from.

---

## 1. Headline figures

| Metric | Value |
|---|---|
| Total recorded live API spend, all lanes | **$73.39** |
| Billed calls | 402 of 405 recorded invocations |
| Input tokens | 2,212,748 |
| Output tokens | 621,395 |
| Corpus spend (`traces/example` only) | $40.45 across 95 bundles |
| Auto-merge bundles with cost data | 22 ($8.20 total) |
| **Cost per merge-ready bundle (mean, N=22)** | **$0.3726** |
| Human-review-required bundles with cost data | 73 ($32.26 total, mean $0.4419) |

Three invocations carry no cost field. They are recorded as calls and excluded from every dollar
figure rather than counted as zero, per the honest-or-null rule the retry accounting adopted on
27 July 2026.

---

## 2. Per-role aggregates, all lanes

| Role | calls | billed | total $ | mean $/call | in tokens | out tokens |
|---|--:|--:|--:|--:|--:|--:|
| patcher | 175 | 173 | $59.35 | $0.3431 | 1,042,894 | 316,266 |
| reviewer | 168 | 167 | $7.36 | $0.0441 | 911,221 | 194,253 |
| reproducer | 62 | 62 | $6.69 | $0.1078 | 258,633 | 110,876 |
| **total** | **405** | **402** | **$73.39** | | **2,212,748** | **621,395** |

The Patcher is 81 percent of spend on 43 percent of the calls. Output tokens are why: an Opus
patch bills at $75 per million out against $15 per million in, so a single long payload costs more
than the whole bundle context that produced it. The Reviewer stays an order of magnitude cheaper
because its output is a verdict and a handful of citations, and the Reproducer sits between the
two because a fixture is real code.

That ratio is the argument for every free gate the pipeline has grown. `bundle preflight`,
`preflight --patch-diff`, `rationale-binding` and the probe each cost nothing and each can stop a
run before the next paid role reads a payload that was never going to survive.

---

## 3. Per-model aggregates

| Model | billed calls | total $ | mean $/call |
|---|--:|--:|--:|
| claude-opus-4-7 | 170 | $58.16 | $0.3421 |
| claude-sonnet-4-5-20250929 | 204 | $13.25 | $0.0650 |
| claude-opus-4-8 | 3 | $1.19 | $0.3980 |
| claude-sonnet-4-6 | 25 | $0.79 | $0.0317 |

The split is deliberate. Opus authors patches, Sonnet reviews and writes fixtures, and the
cross-family rule keeps the Reviewer in a different family from the Patcher that produced the
diff it is grading.

---

## 4. History

Cost per merge-ready bundle, from each generated throughput report:

| Report | N | mean $ | corpus total $ |
|---|--:|--:|--:|
| 2026-05-12 | 3 | $0.2240 | |
| 2026-05-25 | 3 | $0.2667 | |
| 2026-05-26 | 6 | $0.3518 | |
| 2026-06-15 | 14 | $0.3311 | |
| 2026-06-17 | 24 | $0.3772 | |
| 2026-07-21 | 22 | $0.3726 | $27.58 |
| 2026-09-09 | 22 | $0.3726 | $40.45 |

Two things in that table deserve stating plainly rather than being left for a reader to notice.

**The merge-ready mean has been flat since June.** It sat at $0.3772 on 24 data points and
$0.3726 on 22, and the earliest N=3 estimate of $0.22 was low rather than the later figures being
inflated. Roughly $0.37 per merge-ready bundle is the number to quote, and it has survived an
eightfold increase in sample size without moving.

**The merge-ready count has not grown since June, and corpus spend has.** N went from 24 to 22 as
bundles were reclassified, while corpus spend rose $12.88 between 21 July and today. All of that
growth landed in `human-review-required`, whose mean ($0.4419) now exceeds the auto-merge mean.
Read directly: the last seven weeks of live spend bought evidence, retirements and contract
findings rather than new merge-ready bundles. Whether that is a good trade depends on what the
work was for, but the report should not be read as throughput.

Recent deltas, measured against the report dates:

- since 2026-06-17: 166 billed calls, $33.55
- since 2026-07-21: 74 billed calls, $19.12

---

## 5. What this report does not count

The totals above are complete for what the pipeline instruments, and the pipeline does not
instrument everything. In rough order of size:

1. **Model-eval and LoRA spend.** The authoring accuracy runs, the Reviewer-LoRA gate pilots, the
   frontier baselines and the compound probes all wrote artifacts to `data/reports/`, and none of
   those artifacts carry a usage or cost field. `authoring-accuracy-vs-human-2026-09-04.json`
   records dispositions and results with no token counts at all. This spend is real and its size
   is not recoverable from the repository.
2. **HF Jobs GPU time** for LoRA training, billed by the hour rather than by the token and never
   written to any artifact here.
3. **CI compute.** Every cert run, probe and `nix build` is GitHub Actions minutes on a private
   repository.
4. **Work in scratch directories.** The assimp CVE-2026-82591 adaptation canary billed roughly
   $0.85 on 8 September, and its bundle lives outside the repository, so it appears in no total
   above.

Closing the first gap is the obvious next instrumentation slice: the eval drivers already receive
adapter responses carrying usage, and they discard it.

---

## 6. Reproducing these numbers

```
trace report throughput
```

writes a timestamped JSON and Markdown pair to `data/reports/`. It reads the sidecars on disk and
live scout telemetry from the `scout-telemetry` branch, so it is deterministic given a checkout.
The all-lanes tables in sections 2 and 3 come from the same sidecars, globbed across
`traces/*/*/` rather than `traces/example/`.
