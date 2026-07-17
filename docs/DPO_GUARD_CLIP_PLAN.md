# DPO on the authoring-LoRA guard-clip failure — dataset + success metric

**Status:** definition (pre-training). Opened 2026-07-17 as the direct edit-shape lever
from the authoring edit-precision thread (`FINDINGS_LORA.md` line 141).

## The failure being targeted

The authoring-LoRA (`Qwen2.5-Coder-14B` QLoRA, e.g. `authoring-lora-v10-clean`) localizes
the fix site and hits the fix concept, but at the **addition site** it emits the wrong
*edit shape*: it inserts a separate clamp/guard block (**guard-clip**, e.g.
`if (len > max) len = max;`) where the upstream fix **folds the existing condition**
(**condition-fold**, e.g. adds `&& state->head->extra < state->head->extra_max` to the
existing `if`). Greedy single-shot canary add-recall is ~0; verifier-guided pass@16 best-of
recovers add-recall to 0.36 (the production lever). DPO is the direct lever: teach the model
to *prefer* the fold shape over the clip shape, so greedy output improves without sampling.

## Why not a pure "from-archived-failures" dataset

Measured (2026-07-17, `/tmp/dpo_harvest.py`): the archived guard-clip generations number
**18 clean clip-shaped rejects** — zlib 6, requests 6, pyjwt 5, bzip2recover 1 — and **all
18 sit on the 4 eval canaries**. Training DPO on canary prompts would contaminate the only
held-out eval. So the archived failures are used to **calibrate the guard-clip detector**
and as a diagnostic, but **not** as training prompts.

## Dataset definition (preference pairs)

Chat-format preference records `{prompt, chosen, rejected}`:

- **Prompt set** — the training prompts of the **SFT seed adapter**
  (`adastracomputing/authoring-lora-v10-clean`, corpus `authoring-lora-data-v10-clean`,
  68 rows), restricted to the **53 comparison-bearing** prompts (25 condition-fold +
  28 add-comparison; 15 pure-insertion excluded), fully **disjoint from the 4 canaries**.
  These carry the fold-vs-clip contrast DPO needs. (An earlier count of 89/109 was on the
  older v9 corpus; the seed adapter trains on the clean 68-row corpus, so its prompts are
  the correct DPO distribution.) The generation pass samples all 68 and tags each row
  `comparison_bearing` so the filter is transparent.
- **chosen** — the reference upstream fix diff (the assistant turn), which is the
  condition-fold shape.
- **rejected** — the model's **own guard-clip generation** for that prompt, harvested
  **on-policy** (K≈8–16 samples per prompt, temperature ≈0.8 from the current SFT adapter),
  kept only when the sample is (a) wrong (`norm_exact = 0` vs the reference) **and**
  (b) guard-clip-shaped per the detector (adds a fresh clamp assignment or `if`-guard
  instead of modifying the existing comparison). The detector is calibrated against the
  18 archived canary clips.
- Pairs where the model never produces a clip on a prompt (it is already correct) are
  dropped — no synthetic negative is fabricated for them.

On-policy (the model's real failures) is preferred over synthetically rewriting each fold
ref into a clip: the reviewer hard-negative arc (2026-07-16/17) showed **synthetic negatives
can teach a spurious pattern**. On-policy rejects are the model's actual attractor mass.

*(Open fork — codex consult 2026-07-17: on-policy train-harvest vs synthetic-clip
construction; recorded below once the peer replies.)*

## Held-out eval + minimal success metric

- **Eval:** greedy single-shot on the **4 canaries** (zlib, requests, pyjwt, bzip2recover),
  graded ladder (`lora/score_canaries_graded.py`): `add_recall`, `norm_exact`,
  `key_token_frac`, `rem_recall`.
- **Baselines to beat:** SFT greedy mean canary `add_recall` ≈ 0; SFT pass@16 best-of
  `add_recall` = 0.36.
- **Minimal success (preregistered):**
  1. **Primary** — greedy mean canary `add_recall` rises from ~0 to **≥ 0.20** (DPO pulls a
     meaningful share of the sampling-only gain into greedy output), **and**
  2. **Shape flip** — zlib specifically produces the `extra_max` **condition-fold**
     (`key_token_frac` up, clip detector no longer fires), demonstrating the attractor broke
     on the canonical case, **and**
  3. **No regression** — `rem_recall` (deletions it already gets right) does not drop, and
     **pass@16 `add_recall` stays ≥ 0.36** (DPO must not collapse sampling diversity — the
     production lever must survive).
- **Clean-negative outcome** (documented, not hidden, per the two reviewer-arc precedents):
  if greedy add-recall does not clear 0.20 or pass@16 regresses, DPO is retired for this
  failure at this corpus scale and pass@K sampling remains the production lever.

## Build + train steps (after the definition is accepted)

1. Generation pass: sample the SFT adapter K× on the 89 train prompts (HF Jobs, detached).
2. Harvest `{prompt, chosen, rejected}` with the calibrated clip detector; report pair count.
3. DPO train from the SFT adapter seed (TRL `DPOTrainer`, same base), detached, `--timeout 3h`.
4. Greedy canary eval + pass@16 guardrail; score with the graded ladder.
5. Document result (beat/no-beat vs the preregistered metric) in FINDINGS_LORA + DECISIONS.

---

## Result (2026-07-17) — negative, DPO retired

Validated harness (SFT control reproduces pass@16 add_recall 0.36 exactly at 1024 tokens).
Greedy / pass@16 canary add_recall:

| adapter | greedy | pass@16 |
|---|---|---|
| SFT seed (v10-clean) | 0.00 | **0.36** |
| DPO β0.1 lr5e-6 2ep | 0.00 | 0.02 |
| DPO β0.5 lr1e-6 1ep | 0.00 | 0.11 |

- **Primary metric (greedy ≥ 0.20): FAILED** — 0.00 at both settings; DPO learned no fold shape.
- **Guardrail (pass@16 ≥ 0.36): FAILED** — DPO degraded it in both runs; β only limits the
  damage. `requests` (SFT 1.0) destroyed both times → DPO mode-collapse.

**Retired.** pass@K sampling on the SFT adapter stays the production lever. The 94-pair dataset
+ minter are kept for reference. Harness confound (384-token truncation faking a both-adapter
collapse) found and fixed mid-run — see DECISIONS 2026-07-17. Next edit-shape lever is an open
Fable-directed question (SFT-augment vs KTO vs verifier investment).
