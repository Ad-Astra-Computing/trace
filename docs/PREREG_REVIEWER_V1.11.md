# Preregistration — Reviewer-LoRA v1.11 compound-guard experiment

**Status:** registered before any v1.11 measurement. Probe frozen at
`data/probes/compound-guard-probe-freeze.json`
(sha256 `35b4672a11c4b6ce154e14eabdea5c60ba63760e026d84a75e9ce472f322335b`,
20 rows / 5 families), enforced by `tests/eval/test_probe_freeze.py`.

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

**Stop rule at step 3:** if fewer than **5 rows are discordant**, the sign test
cannot reach p<0.05 even if every flip goes the hypothesized way. In that case do
NOT fire; grow the probe first and report the point estimate to Jason before any
spend.

Caveat: if the hard positives are new training data for the treatment arm, the
existing v1.11 checkpoint is *not* the treatment arm. The pre-stage measures the
discordance base rate and probe power — **not** the treatment effect.

## 4. Seeds

"3 seeds" means **training seeds** — 3 LoRA retrains per arm, including the
control arm, which is currently a single run. Inference is greedy and therefore
deterministic, so inference-seed variation measures nothing. Self-consistency
sampling may be reported as an inference-variance error bar but **must not** be
substituted for training replication, which is the dominant noise term at this
scale.

## 5. Endpoints

- **Primary: RAW verdict**, for both promotion clauses. The diagnostic is
  non-gating, so raw is what production experiences; promoting on
  grounding-corrected verdicts would certify a system we do not ship.
- **Secondary (reported, not gating):** grounding-corrected verdicts.
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

**No rows are excluded, for any reason, after the freeze.** In particular rows
where `check_pc_omission_claim` fires are **kept**: it fires precisely on the
false-reject shape, so excluding them would mechanically flatter whichever arm
produces more of them — outcome-dependent exclusion. They are reported as a
descriptive third category instead.

## 8. Declared limitations (recorded before measurement)

- **20 rows, below the ~24 target.** Power is the binding constraint; this is a
  known shortfall, declared now so a later top-up cannot be outcome-dependent.
- **Unbalanced negatives per family:** libwebp 2, ffmpeg 2, krb5 4, libressl 3,
  libsynthguard 4.
- **Declared shape gaps:** libressl has no off-by-one (pure NULL equality guard,
  no numeric boundary); krb5 has no "guard dropped entirely" (its fix adds one
  disjunct to a 3-term guard, so that edit is identical to "drop added
  conjunct").
- **Selection circularity:** 4 of 5 families are trace-authored source-backports
  and are trace-tractable by construction. Only `libsynthguard` is artifact
  independent — and it is a hand-authored **synthetic** control
  (`CVE-0000-00001`, explicitly not a real advisory), not an independently
  sourced real-world fix. Results must be reported split trace-sourced vs
  external.
- The v1.10 control's raw per-row responses were never persisted, so that
  specific run cannot be re-scored offline. Fixed going forward in `390c042`.

## 9. What a NULL result decides (preregistered)

On null, **v1.11 is not promoted.** The fallback is v1.10 plus promoting
`check_pc_omission_claim` to **gating-with-human-escalation** — a
zero-training-cost mitigation for the quote-then-contradict production risk.
That fallback existing is precisely why the trainings must earn their keep at
step 3.

A null is only informative if instrumented, so the run must record: full raw
per-row responses, decode settings and checkpoint hashes, per-arm data-mix
manifests, the **full discordant-pair table per seed pair** (not just the net —
"nothing flipped" and "flips cancel" are opposite conclusions), the **control-arm
noise floor** from the 3 control seeds' pairwise disagreement, and a
per-row decomposition of extraction accuracy vs verdict accuracy.

If the control-arm noise floor is comparable to the effect sought, a null means
"measurement too noisy at this probe size" — which redirects effort to the probe,
not the recipe.
