# Cost and throughput report, v1.1.0

**Generated**: 2026-09-09 at git `fc5bf229`. Supersedes [COST_REPORT_v1.0.0.md](COST_REPORT_v1.0.0.md)
(2026-06-17), which remains accurate for the corpus freeze it describes.

**Scope**: every live Anthropic API invocation recorded in a
`{patcher,reviewer,reproducer}-invocation.json` sidecar under `traces/`. Deterministic roles
(upstream-ref-resolver, Builder, Steward) make no model call and cost nothing. Section 6 lists
the spend that exists but is still not instrumented, which is the part of this report to read first if
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

Model spend is not the largest line. Section 5 reconstructs GitHub Actions compute at an estimated
$168.61 gross, which puts total instrumented project cost near $242 gross, or roughly $133 to $154
once the monthly Actions allowance is applied.

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

## 5. Continuous integration

GitHub Actions minutes are the project's second cost line, and until now they were listed as
uncounted. This section closes that gap. The repository is private, so every minute is billed
against the account allowance at the standard Linux rate of $0.008 per minute. All twenty
`runs-on` declarations across the seventeen workflows name `ubuntu-latest`, so one rate applies
throughout and no macOS or Windows multiplier enters.

| Metric | Value |
|---|---|
| Workflow runs, 28 April to 9 September 2026 | 2,985 |
| Wall-clock time | 265 hours |
| **Estimated billable minutes** | **21,076 (351 hours)** |
| **Estimated gross compute cost** | **$168.61** |
| Estimated overage after a 2,000 min/mo allowance | $80.76 |
| Estimated overage after a 3,000 min/mo allowance | $59.77 |
| Actions artifact storage | 0.41 GB total, 0.12 GB unexpired |

Billable minutes exceed wall clock because billing rounds each job up to the whole minute and
sums parallel jobs, which across the measured runs works out to 1.29 billable minutes per
wall-clock minute.

Gross cost is what the minutes are worth. What actually reaches an invoice is the overage above
the monthly allowance, and the allowance depends on the account plan. Both readings are given
because the plan is not recoverable from the API surface available here: the billing endpoints
need a token scope this checkout does not carry. The invoice figure lies between $60 and $81.

Where the minutes went:

| Workflow | Est. minutes | Est. gross |
|---|--:|--:|
| bundle-linux-cert | 8,128 | $65.02 |
| ci | 7,566 | $60.53 |
| scout-cron | 3,805 | $30.44 |
| scout-snapshot | 487 | $3.89 |
| scout-cpe-dictionary | 362 | $2.90 |
| steward | 341 | $2.73 |
| all others | 387 | $3.10 |

Per calendar month:

| Month | Est. minutes | Est. gross |
|---|--:|--:|
| 2026-04 | 1,020 | $8.16 |
| 2026-05 | 4,539 | $36.31 |
| 2026-06 | 8,932 | $71.46 |
| 2026-07 | 2,531 | $20.25 |
| 2026-08 | 1,962 | $15.69 |
| 2026-09 (partial) | 2,092 | $16.74 |

June is the whole story. It alone accounts for 42% of the minutes and, under either allowance,
most of the invoice. It is also the month the corpus grew to its current size, so the spike is
cert dispatch rather than waste.

Two structural readings follow. The first is that `ci` costs nearly as much as `bundle-linux-cert`
while proving far less: 1,098 runs of the test suite against 241 certs. The suite runs on every
push, and pushes are frequent because the project commits in small slices. The second is that
`scout-cron` costs $30 to harvest candidates, which is comparable to the model spend it exists to
target, and it runs on a schedule whether or not anyone is reading its output.

**Why these are estimates.** Per-job durations were read for 1,816 of the 2,985 runs before the
GitHub API rate limit cut the walk short. The remaining 1,169 runs are extrapolated from the
measured billable-to-wall-clock ratio of their own workflow, which is the right denominator
because the ratio is driven by job count and job count is a property of the workflow. Measured
runs contribute 16,048 billable minutes of the 21,076 total, so 76% of the figure is read rather
than inferred. The GitHub timing endpoint reports a `billable.total_ms` of zero for every run in
this repository while reporting a non-zero `run_duration_ms`, so it could not be used and this
reconstruction from job timestamps replaced it.

---

## 6. What this report does not count

The totals above are complete for what the pipeline instruments, and the pipeline does not
instrument everything. In rough order of size:

1. **Model-eval and LoRA spend.** The authoring accuracy runs, the Reviewer-LoRA gate pilots, the
   frontier baselines and the compound probes all wrote artifacts to `data/reports/`, and none of
   those artifacts carry a usage or cost field. `authoring-accuracy-vs-human-2026-09-04.json`
   records dispositions and results with no token counts at all. This spend is real and its size
   is not recoverable from the repository.
2. **HF Jobs GPU time** for LoRA training, billed by the hour rather than by the token and never
   written to any artifact here.
3. **Determinate Systems cache and network egress**, which the Nix builds in every cert lean on
   and which bills outside GitHub entirely.
4. **Work in scratch directories.** The assimp CVE-2026-82591 adaptation canary billed roughly
   $0.85 on 8 September, and its bundle lives outside the repository, so it appears in no total
   above.

Closing the first gap is the obvious next instrumentation slice: the eval drivers already receive
adapter responses carrying usage, and they discard it.

---

## 7. Reproducing these numbers

```
trace report throughput
```

writes a timestamped JSON and Markdown pair to `data/reports/`. It reads the sidecars on disk and
live scout telemetry from the `scout-telemetry` branch, so it is deterministic given a checkout.
The all-lanes tables in sections 2 and 3 come from the same sidecars, globbed across
`traces/*/*/` rather than `traces/example/`.

The continuous-integration figures in section 5 come from a separate walk of the GitHub Actions
API, regenerated with

```
scripts/ci_minutes.py --out data/reports/ci-minutes-<date>.json
```

whose committed output is
[`data/reports/ci-minutes-20260909.json`](../data/reports/ci-minutes-20260909.json). That walk
needs network access and a GitHub token, so unlike `trace report throughput` it is not
deterministic given a checkout alone.
