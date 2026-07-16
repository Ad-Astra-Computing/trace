# trace — LoRA training-corpus findings

**Status:** running record, updated 2026-07-13. Companion to [`FINDINGS_v0.md`](FINDINGS_v0.md) (the certification-pipeline result); this doc covers the fine-tuning arc built on top of it.
**Companion docs:** [`CONCEPTS.md`](CONCEPTS.md) (pipeline orientation), [`REVIEWER_LORA_PILOT.md`](REVIEWER_LORA_PILOT.md), [`AUTHORING_TRAINING.md`](AUTHORING_TRAINING.md), [`DECISIONS.md`](DECISIONS.md) (running log).

This is the presentation source of truth for the fine-tuning work. Every headline below is stated with its real evidence and confidence, so no claim leaves this file stronger than the data supports. For the standalone external summary of the authoring edit-precision investigation (result, lever, ceiling, limits), see [`AUTHORING_INVESTIGATION.md`](AUTHORING_INVESTIGATION.md).

---

## The two tracks in one paragraph

trace's certification pipeline (v0) uses frontier models (opus/sonnet) for the two model-backed roles, Patcher and Reviewer. The fine-tuning arc asks whether an **open-weight 14B model, fine-tuned on trace's own certified corpus, can take those roles** — so production needs neither a frontier API nor, for authoring, the upstream fix commit. There are two independent tracks. The **Reviewer track** (easier: a binary accept/reject on a proposed patch) is the pipeline dry-run. The **Authoring track** (harder: write the source fix from the vulnerability description alone) is the one that answers the "it's just a version-bump bot" critique, because the label is a real code fix and the fix symbols are scrubbed from what the model sees.

---

## Glossary (read this before the findings)

- **version-bump vs source-backport.** A *version-bump* fix just raises a package to a release that already contains the upstream fix. A *source-backport* fix applies the actual code change to the pinned source. The Authoring corpus is entirely source-backports: there is no version number to bump, the model must author the code.
- **Reviewer-LoRA vs Authoring-LoRA.** Two separately fine-tuned adapters on the same base (Qwen2.5-Coder-14B). Reviewer-LoRA judges a patch (accept/reject). Authoring-LoRA writes a patch.
- **authoring pair.** One training example: input = CVE description (vulnerability only, fix symbols scrubbed) + pre-fix source window; label = the curated upstream fix as a unified diff.
- **leak scrub / grounding.** Two integrity gates on an authoring pair. *Leak scrub* removes the fix's giveaway symbols from the description so the model is not handed the answer. *Grounding* requires the label to edit only code the model was actually shown.
- **cert-green vs behavioral-only (Tier A / Tier B).** A *cert-green* pair carries a full signed evidence bundle (Patcher + Reviewer + Builder + signature). A *behavioral-only* pair is validated by build behaviour alone (unpatched fires the bug, patched is clean) without the full ceremony. Both are honest training labels; the tier is recorded in provenance.
- **canary.** A held-out CVE never seen in training, used to measure generalization (zlib, bzip2recover, requests, pyjwt).
- **localization vs edit-precision.** Two independent authoring skills. *Localization* = find the right line/block to change. *Edit-precision* = make the exactly-correct edit at that site. A model can have one without the other.
- **cohort / fold.** A frozen evaluation set. A *held-out fold* must be disjoint from training for its numbers to mean anything.

---

## Reviewer track — the honest result

**Claim, stated honestly: on a fresh, family-disjoint 34-example fold (3x the old one), Reviewer-LoRA does NOT match frontier on verdict substance. It is accept-biased — it waves through ~47% of bad patches — and frontier beats it cleanly. What survives is a narrower, honest win: the LoRA is more reliable at producing well-formed schema output. It is not production-ready as an autonomous accept/reject gate.**

The larger fresh-data eval (the gate this section previously flagged as "the next real evidence") is now run, and it overturns the old n=11 headline.

What the numbers actually are, on the fresh 34-fold (`data/splits/reviewer-v2-bigfold.json`, 19 accept / 15 reject, family-disjoint, retrained on the remaining 92; job `6a568c3885d9643ce16d31b4`):

| Model | verdict-substance | false-accept | false-reject | schema-conformance |
|---|---|---|---|---|
| **Reviewer-LoRA** | **0.794** (27/34) | **7** | 0 | 1.000 |
| frontier sonnet-4-6 | 0.971 (33/34) | 0 | 0 | 0.65 |
| frontier opus-4-8 | 0.941 (32/34) | 0 | 0 | 0.56 |

- The LoRA accepts **19/19 positives** but rejects only **8/15 negatives** — a pronounced **accept-bias**, and the misses are in the dangerous direction (false-accept = shipping a bad patch).
- Frontier (both models) is near-perfect on verdict correctness with **zero false accepts**.
- The old **n = 11** fold that produced "matched frontier / 11/11 vs 10/11" was **saturated** (reused as a release gate across 11 adapter versions) and had too few hard negatives to expose the accept-bias. That result is retired.
- The one honest LoRA advantage that survives: **schema-conformance 1.0 vs frontier 0.56-0.65** — the LoRA reliably emits the exact `review.md` schema; frontier writes a correct verdict but often adds prose the strict parser rejects. This is a **format** win, not a judgement win.

**Confidence: the fresh fold is clean (genuinely disjoint, no leakage or duplication). The honest conclusion is that Reviewer-LoRA is NOT an autonomous gate — its verdict substance trails frontier and errs toward accepting bad patches. Its production value is schema-shaped drafting under a frontier or human accept check. The earlier "matches frontier on verdicts" claim is refuted on fresh data.**

### Where the accept-bias comes from (2026-07-15 diagnostic)

A free diagnostic on the LoRA's own output splits the 7 false-accepts into two distinct causes:

- **4 semantic misses** (condition-mutation ×3, misplacement ×1): the LoRA's own `## Patch comparison` transcribes both guards and declares them **"match"**, then accepts — genuine blindness at the char-level comparison step, not a verdict-first miscalibration. This is the 14B-from-~100-examples ceiling. Fix = training (contrastive condition hard-negatives, Fable #1).
- **3 metadata misses** (version-without-hash, wrong-src-hash, rationale-cites-wrong-version): the model never examines these fields. Fix = the contract layer, not the model.

### The contract-layer gate (shipped)

`agents/reviewer/metadata_lint.py` is a deterministic metadata-consistency gate grounded in `upstream-ref.json` (trusted resolver output). It settles version/hash consistency mechanically, with **zero false-positives across all 31 honest positives**. Shipped as a reject-if-fires gate beside the model:

| Configuration | fresh 34-fold substance | false-accept | false-reject |
|---|---|---|---|
| Reviewer-LoRA alone | 0.794 (27/34) | 7 | 0 |
| **Reviewer-LoRA + deterministic lint** | **0.853 (29/34)** | **5** | 0 |
| frontier sonnet-4-6 | 0.971 | 0 | 0 |
| frontier opus-4-8 | 0.941 | 0 | 0 |

The gate removes both metadata false-accepts (adminer, dropbear) at zero compute cost and zero false-reject risk — the architecturally-honest shape (contract layer settles field checks, model handles code semantics). The remaining 5 false-accepts are the char-level guard-comparison misses; closing them is the retrain arc, not another gate.

---

## Authoring track — the honest result

**Claim, stated honestly: data scale and diversity is the lever that moves localization; edit-precision remains the open gap. The fine-tuned 14B locates the right fix site but does not yet reliably produce the exact edit.**

- Across four training runs (v1.0 to v1.3) scored on the 4 held-out canaries, byte-exact match stayed at 0/4.
- The signal is in *where the model looks*: single-example additions moved canary localization zero, while a 15-example stratified batch (v1.3) recovered zlib localization to the true fix site on both the full and the distractor-narrowed window. That is the first movement in four runs and it tracks data scale, not prompt tweaks.
- The residual gap is edit-precision (guard-clip vs the upstream condition-fold at a correct site) and uneven transfer (the gain concentrated on one canary, not all four).
- For reference, frontier sonnet zero-shot scores ~2/4 structural on the same canaries, so the task is hard even for a frontier model authoring from the vulnerability alone. That difficulty is itself the corpus-value evidence: this is not fix-copying.

**Confidence: the localization-lever claim is validated. The path forward is more clean data, then re-baseline, then decide on a stronger base.** Note the important caveat below: the v1.0-v1.3 canary results predate a corpus-integrity fix, so some of the 0/4 may be corpus noise rather than a model ceiling. The current 14B should be re-baselined on the cleaned corpus before that ceiling is trusted.

---

## Corpus integrity (2026-07-13) — the load-bearing gate

An adversarial review of the authoring corpus (independently verified against the artifacts) found **~12 of 91 exported training rows were compromised**:

- **8 pairs** whose label edited code absent from the shown window (the model was asked to author a change to code it never saw),
- **1 answer-key leak** (a "vulnerable" window cut from a half-patched tree, with the fix already present),
- **3 redundant duplicates** that escaped dedup.

Root cause: the grounding and dedup gates ran only when a pair was first minted, so a cached pair written by an older exporter bypassed them at export. The fix moves the gates to export time, over every emittable pair, cached or fresh:

1. **Per-file grounding** — every file the label edits must be shown, and each file's removed lines must appear in that file's own window section (not merely somewhere in the combined input).
2. **Self-leak guard** — a pure-addition fix whose block already sits contiguously in the window (a half-patched tree) is excluded.
3. **Edit-based dedup** — pairs are keyed on the edit (per-file paths, hunk positions, changed lines), not the window, so a redundant re-window collapses while genuinely distinct edits stay separate.

All three run over one correct unified-diff parser. **Export is now 91 → 79 honest rows**: every pair edits only shown code, no pair hands over the fix, no duplicates. This is the corpus the next training run should use.

---

## Honest claim ledger

| Claim | Evidence | Confidence |
|---|---|---|
| The pipeline certifies simple-trigger memory-safety CVEs and honestly refuses the rest | 8 cert-green + 8 retired, [`FINDINGS_v0.md`](FINDINGS_v0.md) | High |
| The authoring task is real fix-authoring, not version-bumping or fix-copying | 79 grounded, leak-scrubbed source-backport pairs; frontier scores only ~2/4 zero-shot | High |
| The authoring training corpus is honest (no answer-key, no ungrounded labels) | export-time integrity gates, 91→79 rows, 2026-07-13 | High |
| Data scale + diversity moves authoring localization | v1.3 zlib localization recovery vs zero movement from single-example runs | Medium |
| Core localization survives on a fully behaviorally-validated corpus | v10 clean re-baseline: zlib localizes to the `extra_max` site on the narrowed window (2026-07-14) | Medium |
| Grafting the (unvalidated) supplements back restores distractor-resistance | v11 supplemented re-baseline: NOT cleanly — full-window recovered the bound but with hallucinated asm, narrowed regressed; byte-exact still 0/4 | Not supported |
| Edit-precision (byte-exact) is the ceiling and is insensitive to corpus cleanliness AND to +21 stratified examples | 0/4 byte-exact identical across v1.3 (dirty 109), v10 (clean 68), v11 (clean 89) | Medium-High |
| byte-exact-on-free-form-diff overstated the ceiling — it hides real partial edit-correctness | graded re-score (2026-07-14): pyjwt removed-line recall 1.0 (right deletion, wrong add-shape) across all 3; requests v11-narrowed added-line recall 1.0; zlib = right concept (`extra_max`) different line structure. Residual gap = edit-SHAPE at the addition site (guard-clip vs condition-fold) | Medium |
| The byte-exact ceiling is largely a FORMAT artifact; the model has learned the edits | memorization (2026-07-14): v10 reproduces its OWN train labels at 1/10 byte-exact but norm-exact 6/10, add-recall 0.90, rem-recall 0.93 | Medium-High |
| Verifier-guided sampling (pass@K) is the production lever | pass@16 lifts best-of-K add-recall 0->0.36 (requests 1.0, zlib 0.33); LoRA useful despite non-byte-exact single-shot | Medium |
| The search/replace FORMAT change alone does not move held-out edit-precision | v10->SR greedy: add-recall 0.00 (= v10), rem 0.25; caveat: no loss-masking, greedy only | Medium |
| Base-model capacity is not the lever — no base beats the fine-tuned 14B + sampling | 7-model probe (2026-07-14): frontier opus-4-8 0.00 / sonnet-4-6 0.25, and the real candidates via CF Workers AI — GLM-5.2 0.02, Qwen3-30B (bzip2 norm-exact, timeouts), Qwen2.5-Coder-32B 0.25/1-of-4 — none beat the 14B pass@16 add-recall 0.36; all share the concept-right/add-wrong failure | Medium-High |
| The fine-tuned 14B reliably authors correct fixes | 0/4 canary byte-exact across v1.3/v10/v11; localization only, noise-dominated | Not yet supported |
| Reviewer-LoRA matches frontier on verdicts | REFUTED on fresh 34-fold: LoRA 0.794 (7 false-accept) vs sonnet 0.971 / opus 0.941 (0 fa) | Not supported — retired |
| Reviewer-LoRA is accept-biased (waves through bad patches) | fresh 34-fold: accepts 19/19 positives but only rejects 8/15 negatives | High |
| Reviewer-LoRA's real win is schema-format reliability, not verdict correctness | fresh 34-fold: LoRA schema-conformance 1.0 vs frontier 0.56-0.65; verdict substance trails | High |
| Reviewer-LoRA beats frontier as a capability | one-example parse artifact (n=11); refuted on fresh 34-fold | Not supported — retired |

---

## Edit-precision thread — resolved (2026-07-14)

The authoring edit-precision question is answered with a defensible **lever / ceiling** result:

- **Lever (production):** verifier-guided sampling — pass@K over the LoRA, filtered by the existing behavioral reproducer. pass@16 lifts best-of-K add-recall from ~0 to 0.36 (requests 1.0). The LoRA is useful despite non-byte-exact single-shot output; the LoRA localizes + hits the fix concept, sampling + a verifier recovers correct edits.
- **Ceiling:** greedy single-sample edit-shape at the addition site, at this dataset size (~60-89 rows). Insensitive to corpus scale/cleanliness (three flat re-baselines) and to the search/replace format change alone.
- **Retired:** "more data fixes it", byte-exact-on-free-form-diff as a metric, the bare "beats frontier" framing.
- **Durable wins:** export-time integrity gates (91->79 honest corpus) + honest measurement (graded ladder, memorization diagnostic, this ledger).

## What's open (lower priority, not required for the result)

- **SR + loss-masking**, and an **SR pass@K** — the untested half of the format intervention.
- **DPO on the model's own guard-clip failures** — the direct edit-shape lever.
- **FIM / bigger base** — codex/Fable ranked last; only if the above stall.
- ~~**Fresh-data Reviewer eval** larger than n=11~~ — DONE (2026-07-14, 34-fold): LoRA 0.794 with 7 false-accepts, does not match frontier. Next: close the accept-bias (negative-heavy retraining / calibrated reject threshold) before any "matches frontier" claim is defensible.
- **Corpus hygiene** — physically retire the redundant double-bootstrap + giflib half-patched dirs (the exporter already excludes them; cleanup, not correctness).
