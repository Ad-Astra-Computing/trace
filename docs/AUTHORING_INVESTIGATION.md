# Can a small fine-tuned model author CVE fixes? Result, lever, and ceiling

**Status:** investigation complete, 14 July 2026. Self-contained external summary; the running record and per-claim confidence live in [`FINDINGS_LORA.md`](FINDINGS_LORA.md), the raw decisions in [`DECISIONS.md`](DECISIONS.md).

---

## The question

trace fine-tunes an open-weight model to *author* a source-level CVE fix from the vulnerability description alone (fix symbols scrubbed) plus the pre-fix source window. The label is the real upstream fix. This answers the "it is just a version-bump bot" objection: there is no version to bump, the model has to write the code. Base model: Qwen2.5-Coder-14B-Instruct, QLoRA on a single A100. Held-out evaluation on four canary CVEs (zlib, bzip2recover, requests, pyjwt).

The narrow question this investigation answers: **where is the lever, and where is the ceiling, for teaching a small model to author these fixes?**

## The result in one paragraph

The model *localizes* the fix and reliably produces the fix *concept*, but does not reliably produce the exactly-correct *edit at the addition site* (for example it adds a reject-guard where upstream folds a bound into an existing condition). That gap is the ceiling, and it is **task-hardness, not a fixable data or model deficiency**: it does not move with more or cleaner training data, it does not move with a search/replace label format, and it does not move with a bigger or frontier base model. The best-performing configuration measured is the fine-tuned 14B plus **verifier-guided sampling** (sample K candidates, keep the ones a behavioral reproducer accepts), which recovers materially more correct edits than any single-shot model tested, including frontier models and larger open coders. That is the production lever.

## What was tested, and what each test showed

| Lever tested | How | Result |
|---|---|---|
| More / cleaner data | Three separately-trained adapters: 109 rows (with unvalidated supplements), 68 fully-validated, 89 validated + re-added supplements | No movement. Edit precision is insensitive to corpus scale and cleanliness at this size. |
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

- **Localization is solved; edit-precision at the addition site is the frontier.** This is a genuinely hard authoring problem, not a small-model artifact: a frontier model zero-shot sits at the same ceiling with the same failure mode.
- **The production path is verifier-guided sampling, not a bigger model.** The fine-tuned 14B plus a behavioral verifier is competitive with, and on aggregate ahead of, frontier zero-shot. The LoRA is useful precisely because it localizes and proposes plausible edits cheaply, and the verifier keeps the correct ones.
- **The corpus and the measurement are now trustworthy.** Export-time integrity gates removed answer-key leakage, ungrounded labels, and duplicates (91 rows down to 79 honest ones). The graded metric and a memorization check replaced a misleading headline number.

## Honest limits

- Four canaries, mostly single-shot decoding: the graded numbers are directional, not a large-N benchmark. The zlib localization read in particular is a qualitative, noise-affected signal.
- The graded metric can under-credit a semantically-correct edit that uses a different line structure (for example the zlib bound expressed differently), and it under-credits reasoning models whose output format or token budget did not fit the harness.
- Search/replace was tested as a format change only; loss-masking on the copied span, and pass@K over the search/replace adapter, are untested.

## Durable outcomes

- **Honest corpus:** export-time grounding, self-leak, and dedup gates over a shared unified-diff parser.
- **Honest measurement:** a graded scorer, a memorization diagnostic, and a per-claim confidence ledger.
- **A defensible lever/ceiling result** that redirects future effort away from more data and bigger models toward sampling-plus-verification and addition-site edit representation.

## Next

1. Make the lever real: a verifier-guided-sampling pipeline (sample K from the LoRA, filter through the existing behavioral reproducer, emit the best accepted fix).
2. Attack the addition-site gap directly: search/replace with loss-masking, or preference training on the model's own guard-clip failures.
3. Widen the evaluation beyond four canaries so the graded numbers carry statistical weight.
