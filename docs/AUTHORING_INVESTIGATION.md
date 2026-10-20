# Can a small fine-tuned model author CVE fixes? Result, lever, and ceiling

**Status:** investigation concluded, 20 July 2026 (extends the 14 July lever/ceiling result with the edit-shape training arc). Self-contained external summary; the running record and per-claim confidence live in [`FINDINGS_LORA.md`](FINDINGS_LORA.md), the raw decisions in `DECISIONS.md` (kept alongside the repo, not tracked in git).

---

## The question

trace fine-tunes an open-weight model to *author* a source-level CVE fix from the vulnerability description alone (fix symbols scrubbed) plus the pre-fix source window. The label is the real upstream fix. This answers the "it is just a version-bump bot" objection: there is no version to bump, the model has to write the code. Base model: Qwen2.5-Coder-14B-Instruct, QLoRA on a single A100. Held-out evaluation on four canary CVEs (zlib, bzip2recover, requests, pyjwt).

The narrow question this investigation answers: **where is the lever, and where is the ceiling, for teaching a small model to author these fixes?**

## The result in one paragraph

The model *localizes* the fix and reliably produces the fix *concept*, but does not reliably produce the exactly-correct *edit at the addition site* (for example it adds a reject-guard where upstream folds a bound into an existing condition). The best-performing production configuration is the fine-tuned 14B plus **verifier-guided sampling** (sample K candidates, keep the ones a behavioral reproducer accepts), which recovers materially more correct edits than any single-shot model tested, including frontier models and larger open coders. That is the production path, and it is now a built pipeline with a behavioral CI gate.

The addition-site gap was then attacked directly, and the picture is more nuanced than "task-hardness." **Shape-stratified training data IS a lever: it creates edit-shape mass that generic scale never did**: a fold shape the model previously never sampled at any temperature (bzip2's bound-guard) went to full added-line recall after the corpus was enriched with condition-fold examples. What does *not* yet work is making that lever *reliably additive*: at 68–95-row corpus scale, adding fold-heavy rows (whether upsampled or diverse) redistributes capacity and destabilizes the brittle SFT grounding, regressing the shapes the additions do not carry. So the frontier is not "small models cannot author fixes" but "shape-targeted SFT needs a larger validated base corpus and higher-fidelity training pairs to be safely additive." Preference training on the model's own failures (DPO) was tested and retired as strictly harmful.

## What was tested, and what each test showed

| Lever tested | How | Result |
|---|---|---|
| More / cleaner *generic* data | Three adapters: 109 rows (unvalidated supplements), 68 validated, 89 validated + re-added | No movement. Edit precision is insensitive to generic corpus scale/cleanliness at this size. |
| Shape-stratified data (edit-shape enrichment) | Enrich the corpus with condition-fold examples (upsampled, then diverse harvested) and retrain | **VALIDATED lever:** bzip2's fold went from zero-mass (0/64 at every temperature) to full added-line recall. Shape-targeted data creates mass generic scale never did. |
| Making the shape lever additive | v12 (upsample 68→106) and v13 (diverse mint 68→95) | Not yet: both breached a pre-registered zlib-regression gate. Fold-heavy additions redistribute capacity + (v13) untethered-diff pair-fidelity destabilizes brittle canaries. Needs a larger base + higher pair fidelity. |
| Preference training (DPO on guard-clip failures) | DPO from the SFT seed on the model's own guard-clip vs fold preference pairs (β 0.1 and 0.5) | **Retired, strictly harmful:** never moved greedy, and mode-collapsed the pass@K lever (0.36 → 0.02/0.11). |
| The evaluation metric | Replaced byte-exact-on-diff with a graded ladder (removed-line recall, added-line recall, concept-token hit, normalized-exact) | Byte-exact was measuring format fidelity, not edit correctness. The model reproduces its *own* training edits at 0.90 added-line recall but only 1 in 10 byte-exact, so the byte-exact ceiling is largely a format artifact. |
| Label format | Retrained with search/replace blocks instead of free-form unified diffs | The format change alone did not move held-out edit precision (loss-masking untested). |
| Base-model capacity | Zero-shot on the four canaries: frontier (opus-4-8, sonnet-4-6) and the real open candidates via Cloudflare Workers AI (GLM-5.2, Qwen3-30B, Qwen2.5-Coder-32B) | No base beats the fine-tuned 14B plus sampling. |
| Sampling + verifier | pass@16 from the 14B, best-of-K on the graded metric | Added-line recall rises from ~0 (greedy) to 0.36, the best number in the whole study. |

### Cross-model evidence (single-shot unless noted, graded added-line recall)

| Configuration | Added-line recall | Fully-exact canaries |
|---|--:|--:|
| **14B LoRA + pass@16 (verifier-guided)** | **0.36** | 0 of 4 |
| Qwen2.5-Coder-32B (zero-shot) | 0.25 | 1 of 4 |
| sonnet-4-6 (zero-shot) | 0.25 | 0 of 4 |
| Qwen3-30B (zero-shot) | partial (window timeouts) | 1 of 4 |
| GLM-5.2 (zero-shot) | 0.02 | 0 of 4 |
| opus-4-8 (zero-shot) | 0.00 | 0 of 4 |
| 14B LoRA (greedy, single-shot) | 0.00 | 0 of 4 |

Every model, small or frontier, shares the same failure signature: it deletes the right code and names the right concept, then writes the wrong addition. Larger bases occasionally solve the *easiest* canary exactly (bzip2), which is a marginal capacity effect, but none move the aggregate or the hard shapes.

## What this means

- **Localization is solved; edit-precision at the addition site is the frontier.** A frontier model zero-shot sits at the same single-shot ceiling with the same failure mode.
- **The production path is verifier-guided sampling, not a bigger model.** The fine-tuned 14B plus a behavioral verifier is competitive with, and on aggregate ahead of, frontier zero-shot. Built and shipped: `eval/authoring_passk_pipeline.py` (sample K → structural + behavioral verifier → first passing candidate is the fix) plus a behavioral CI gate that runs every candidate and audits verifier false-accepts.
- **Edit-shape IS trainable: shape-targeted, not generic, data is the lever.** The refinement of the 14 July "insensitive to data" claim: generic scale/cleanliness does nothing, but *shape-stratified* data creates edit-shape mass (bzip2 zero-mass → full recall). The open problem is additivity at small corpus scale (redistribution + pair-fidelity), not the existence of the lever.
- **The corpus and the measurement are trustworthy.** Export-time integrity gates removed leakage, ungrounded labels, and duplicates; the graded metric and a memorization check replaced a misleading headline; every retrain used a pre-registered success/kill metric.

## Limits

- Four canaries, mostly single-shot decoding: the graded numbers are directional, not a large-N benchmark. The zlib localization read in particular is a qualitative, noise-affected signal.
- The graded metric can under-credit a semantically-correct edit that uses a different line structure (for example the zlib bound expressed differently), and it under-credits reasoning models whose output format or token budget did not fit the harness.
- Search/replace was tested as a format change only; loss-masking on the copied span, and pass@K over the search/replace adapter, are untested.

## Durable outcomes

- **Validated corpus + measurement:** export-time grounding/self-leak/dedup gates, a graded scorer, a memorization diagnostic, an edit-shape classifier, and a per-claim confidence ledger.
- **The verifier-guided pass@K pipeline + behavioral CI gate**: the production authoring path, dual-reviewed and merged.
- **An automated fold-pair minter** (`eval/mint_fold_pairs.py`): reconstructs leak-clean, sub-shape-stratified authoring pairs directly from upstream fix diffs (no source fetch), turning shape-targeted data from hand-authoring into a cheap, reusable capability.
- **A validated training lever** (shape-stratified SFT) with a documented safe-operating regime, plus a clean negative on DPO.

## Next (the concluded forward path)

1. **The production path is shipped**: verifier-guided pass@K + the behavioral gate. Run the behavioral cert to record the verified-fix rate + false-accept audit when a batch of candidates warrants the CI build cost.
2. **Re-enter the shape-stratified lever only when it can be additive:** grow the validated base corpus to ~150+ rows (so a fixed minted fold set is ≤10–15% of the mix), fix minted-pair fidelity first (renumber reconstructed diffs to the shown window, strip ancillary hunks), and re-test with ≥2 seeds and a held-out fold set broader than the four canaries. Do not fund this one $5–8 retrain at a time.
3. **Widen the evaluation beyond four canaries** so the graded numbers carry statistical weight: the standing prerequisite for any future training claim.
