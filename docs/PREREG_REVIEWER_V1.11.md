# Preregistration — Reviewer-LoRA v1.11 compound-guard experiment

**Status:** registered before any v1.11 measurement. Probe frozen at
`data/probes/compound-guard-probe-freeze.json`
(sha256 `bdebcd7d1081be424cf59fc653211187278713f9e38d05ab3f78246e37712f15`,
**25 rows / 5 families**), enforced by `tests/eval/test_probe_freeze.py`.

**Amendment (pre-measurement, 2026-08-03).** The probe was topped up from 20 to
25 rows BEFORE any inference was run, on peer instruction; the freeze manifest
carries the prior sha256 under `previous_freezes` with
`amended_pre_measurement: true`. Rationale: libwebp and ffmpeg carried only 2
negatives each — and ffmpeg is the family where the v1.10 over-rejection failure
actually lives, so leaving it under-probed invited a "the failure family was
under-probed" objection; and libsynthguard needed a SECOND clean positive
(plain guard vs the existing awkward one) so that a miss there can be attributed
to external-artifact failure rather than awkwardness. This was the last
analytically free moment: after the first measurement any row change would be
outcome-dependent and is forbidden by §7.

**Amendment (process disclosure, 2026-08-03).** At dispatch time the "existing
v1.11 checkpoint" assumed by step 3 was found NOT to exist —
`adastracomputing/reviewer-lora-v1.11` was never trained; the pre-stage design
inherited an incorrect premise. Resolution (peer-ruled): dispatch **one**
control-arm training (seed 42, current corpus, NO hard positives — i.e. one of
the final experiment's 3 control-arm seeds, brought forward) so the registered
v1.10-vs-v1.11-sans-hard-positives comparison can run. Hard cap: this one
training only before the power gate; the remaining 5 (2 control seeds + 3
treatment seeds) stay behind it. If the gate rules futility, this checkpoint is
accepted sunk cost and is NOT an argument for continuing. Documented fallback if
the run fails for infrastructure reasons: v1.9 as second arm — verified clean of
all 5 probe families by construction (trained 2026-06-23; every probe-family
artifact entered the repo 2026-06-28 or later) — at the cost of a bias-direction
amendment (v1.9's larger recipe delta biases discordance HIGH, not LOW).

Authorization: Jason authorized the statistical framing ("Option A"), conditional
on peer endorsement; the peer endorsed it while imposing the staging rule below.
See DECISIONS 2026-08-03.

---

## 1. The question

Can the Reviewer be trained to **reject subtly-wrong compound-guard fixes**
(a dropped conjunct, a flipped operator, an off-by-one, a wrong identifier)
**without becoming trigger-happy and over-rejecting CORRECT fixes from unseen
families**?

This is a behavioral question about the model. It is not answered by the
deterministic `check_pc_omission_claim` diagnostic shipped in `b3e5714`: that is
a *detector, not a correction* — non-gating, and it only fires on an explicit
backticked omission claim contradicting the model's own extraction. A model that
over-rejects via a hedged rationale, a wrong-token claim, or no quoted extraction
passes straight through it.

## 2. Why the question is live

The v1.10 control on the (then 6-row) probe failed in **both** directions:

- it **over-rejected a clean ffmpeg positive** — a quote-then-contradict error:
  the model quoted the full two-conjunct guard in both its patch and upstream
  extractions, then asserted the height conjunct was omitted;
- it **raw-accepted a libwebp drop-conjunct negative**, scoring "correct" only
  because the deterministic grounding layer overrode it.

The scored 5/6 therefore flatters the model.

## 3. Staging rule (hard)

No training is dispatched until (a) the probe is frozen and this document is
registered, and (b) the hard positives are authored — they *are* the treatment
arm's training data, so dispatching without them dispatches the wrong experiment.

Order:

1. Scorer validation — confirm the new diagnostic fires on a REAL response
   artifact, not only synthetic fixtures. (Classified as validation, **not** a
   re-baseline: n=20 with one arm re-baselines nothing.)
2. Probe frozen + prereg registered (this document).
3. **Inference-only power pre-stage** over the frozen probe on EXISTING
   checkpoints. Cheap against a training run. Counts discordant pairs.
4. Six trainings (2 arms x 3 training seeds) **only if step 3 clears**.

### Stop rule at step 3 (corrected arithmetic — this is binding)

An earlier draft said "fire if >=5 discordant." That was wrong in substance. Our
test is a **one-sided** paired sign test; the achievable p by discordant count k
and number of wrong-direction ("defecting") rows is:

| k | perfect split | tolerates 1 defector | tolerates 2 |
|---|---|---|---|
| 5 | 0.031 (ok) | 0.188 — no | no |
| 6 | 0.016 (ok) | 0.109 — no | no |
| 7 | 0.008 (ok) | 0.063 — no | no |
| 8 | 0.004 (ok) | **0.035 (ok)** | no |
| 11 | 0.0005 | 0.006 | **0.033 (ok)** |

So k=5 reaches significance **only on a flawless 5-0 split** — a single
wrong-direction row destroys the primary analysis. Thresholds:

- **k < 5 → STOP.** Cannot reach p<0.05 under any split. Grow the probe, report
  to Jason, do not fire.
- **k = 5-7 → AMBER.** Significant only on a perfect split. Do NOT auto-proceed:
  report to Jason with the discordant table and an explicit statement that one
  defecting row kills the primary. Default recommendation in amber is to grow
  the probe.
- **k >= 8 → GO.** Survives one defector.

(For reference, under a two-sided test the floor would be k>=6; we specify
one-sided, and the thresholds above are computed for the test we actually run.)

### The pre-stage number is biased LOW — recorded before measurement

The 4-6 hard positives are in NEITHER checkpoint, so the pre-stage compares
v1.10 against a v1.11 that has not seen the treatment data. Pre-stage discordance
therefore **underestimates** what the trained arms would show. Consequences,
committed now:

- Low discordance is **ambiguous** between "probe is insensitive" and "recipe is
  inert without its hard positives." It must NOT be read as "the recipe does not
  work."
- The bias runs in the safe direction for a STOP decision (growing the probe is
  cheap relative to 6 trainings), which is why a low reading triggers report-and-
  grow rather than abandonment.

Caveat: if the hard positives are new training data for the treatment arm, the
existing v1.11 checkpoint is *not* the treatment arm. The pre-stage measures the
discordance base rate and probe power — **not** the treatment effect.

## 3.1 Hard-positive accept-pass failure policy (pre-committed, before the pass runs)

The 8 authored hard positives become corpus members only via a live Reviewer
accept pass. Decided BEFORE any pass runs, so the choice cannot be made after
seeing which bundle failed:

- **Reviewer rejects a hard positive → DROP it** (train on fewer). The bundle
  stays in `traces/positives-reorg/` with its reject transcript recorded; it is
  not exported and not reworked.
- **Single exception:** if the rejection names a *mechanical artifact defect*
  (hunk-header arithmetic, file path, staging error) unrelated to the semantic
  equivalence claim, ONE fix + ONE re-run is allowed, and the fix must not
  touch the guard rewrite itself. A second rejection is a drop, no appeals.
- All accept AND reject transcripts are committed, and the treatment corpus is
  frozen + hashed after the pass with the transcripts referenced from its
  manifest.
- **Analysis conditions carried forward (peer, 2026-08-04):** the treatment
  comparison runs against the **v1.11 control recipe** (matched corpus minus
  hard positives — cancels the corpus-growth confound; the pre-stage showed
  that confound alone moves FA 9→14 vs v1.10), and the treatment-stage sign
  test must beat the measured **36% no-treatment discordance base rate**
  directionally, per §6, with the biased-low note restated there.

## 4. Seeds

"3 seeds" means **training seeds** — 3 LoRA retrains per arm, including the
control arm, which is currently a single run. Inference is greedy and therefore
deterministic, so inference-seed variation measures nothing. Self-consistency
sampling may be reported as an inference-variance error bar but **must not** be
substituted for training replication, which is the dominant noise term at this
scale.

### 4.1 Seed aggregation (pre-committed — closes a forking-paths hole)

2 arms x 3 seeds admits many pairings (per-seed tests, 9 cross-pairings, pooled).
We pre-commit to exactly one: **per-row majority verdict across the 3 seeds
within each arm, then a SINGLE paired sign test** over those majority verdicts.
Seed-level disagreement within an arm is reported **descriptively only** and
never enters the test. No alternative aggregation may be substituted after
seeing results.

## 5. Endpoints

- **Primary: RAW verdict**, for both promotion clauses. The diagnostic is
  non-gating, so raw is what production experiences; promoting on
  grounding-corrected verdicts would certify a system we do not ship.
- **Secondary (reported, not gating):** grounding-corrected verdicts.
  **Mechanical definition, frozen before measurement:** "grounding-corrected"
  means the `effective_verdict` produced by `eval/score_gate_pilot.py` at the
  commit pinned in the run manifest — i.e. the existing deterministic overrides
  (`check_pc_file_grounding` / `check_pc_role_grounding` firing on a negative
  canary), and nothing else. No correction may be added, removed or re-tuned
  after measurement begins.
- **Conflict rule (pre-committed):** primary-null + secondary-positive = **NULL**.
  The grounding-corrected secondary is not an escape hatch; it can never rescue
  a null primary.
- **Descriptive:** `check_pc_omission_claim` fire counts per arm x seed;
  grounding-override rate per arm; slices by family x mutation-shape x
  clean/mutated.

## 6. Promotion rule

> Promote v1.11 iff **(i)** net discordant flips (treatment-correct vs
> control-correct) are positive within **every** seed pair, and the pooled
> one-sided sign test over discordant pairs gives **p < 0.05**; **and (ii)**
> paired clean-positive false-rejects (raw) do **not** increase in **any** seed
> pair.

Analysis is **paired per-row** (sign test / McNemar on discordant rows), not a
difference in proportions — dramatically more powerful at this n and it composes
with the paired clean-positive design.

## 7. No post-freeze row exclusions

**No rows are excluded, for any reason, after the freeze.** This extends to
**no family exclusions and no reweighting**: every preregistered slice is
reported even if the result is ugly or embarrassing for a family. In particular rows
where `check_pc_omission_claim` fires are **kept**: it fires precisely on the
false-reject shape, so excluding them would mechanically flatter whichever arm
produces more of them — outcome-dependent exclusion. They are reported as a
descriptive third category instead.

## 8. Declared limitations (recorded before measurement)

- **25 rows** after the pre-measurement amendment (was 20, below the ~24 target). Power is the binding constraint; this is a
  known shortfall, declared now so a later top-up cannot be outcome-dependent.
- **Unbalanced negatives per family:** libwebp 2, ffmpeg 2, krb5 4, libressl 3,
  libsynthguard 4.
- **Declared shape gaps:** libressl has no off-by-one (pure NULL equality guard,
  no numeric boundary); krb5 has no "guard dropped entirely" (its fix adds one
  disjunct to a 3-term guard, so that edit is identical to "drop added
  conjunct").
- **Selection circularity, stated plainly rather than in a footnote:** 4 of 5
  families are trace-authored source-backports and are trace-tractable by
  construction. Only `libsynthguard` is artifact independent, and it is a
  hand-authored **synthetic** control (`CVE-0000-0000{1,2}`, explicitly not real
  advisories), not an independently sourced real-world fix. It therefore
  satisfies **pipeline independence** — the actual confound, that
  pipeline-produced artifacts share quirks a trained model can exploit — but NOT
  real-world provenance. Consequently: **a probe failure on `libsynthguard`
  rules out pipeline overfitting, but a probe pass there is weaker evidence than
  a real independently-sourced fix would be.** Results are reported split
  trace-sourced vs external. The family now carries two clean positives (one
  plain, one awkward) so an external miss is not confounded with awkwardness.
- The v1.10 control's raw per-row responses were never persisted, so that
  specific run cannot be re-scored offline. Fixed going forward in `390c042`.

## 9. What a NULL result decides (preregistered)

On null, **v1.11 is not promoted.** The fallback is v1.10 plus promoting
`check_pc_omission_claim` to **gating-with-human-escalation** — a
zero-training-cost mitigation for the quote-then-contradict production risk.
That fallback existing is precisely why the trainings must earn their keep at
step 3.

**False-positive budget binding the fallback (pre-committed).** The fallback
promotes a diagnostic to a gating role on the strength of a handful of authored
shapes. The pre-stage yields real-artifact false-positive data for free, so the
fallback is bound to it: **if `check_pc_omission_claim` fires on more than 5% of
clean-accept rows in live v1.10 outputs, it is NOT promoted to gating**,
regardless of the primary outcome. A checker that misfires on correct patches
would convert an over-rejection problem into a different over-rejection problem.

A null is only informative if instrumented, so the run must record: full raw
per-row responses, decode settings and checkpoint hashes, per-arm data-mix
manifests, the **full discordant-pair table per seed pair** (not just the net —
"nothing flipped" and "flips cancel" are opposite conclusions), the **control-arm
noise floor** from the 3 control seeds' pairwise disagreement, and a
per-row decomposition of extraction accuracy vs verdict accuracy.

If the control-arm noise floor is comparable to the effect sought, a null means
"measurement too noisy at this probe size" — which redirects effort to the probe,
not the recipe.
