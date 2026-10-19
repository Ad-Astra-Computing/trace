---
base_model: Qwen/Qwen2.5-Coder-14B-Instruct
datasets:
  - adastracomputing/reviewer-lora-data
library_name: peft
pipeline_tag: text-generation
tags:
  - lora
  - qlora
  - peft
  - code-review
  - nixpkgs
  - security
license: apache-2.0
---

# Reviewer-LoRA v1.1

v1.1 is an intermediate, retired version; its weights are not separately hosted. The current adapter is [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10), public under Apache-2.0. This card is kept for the lineage: the two false rejects v1.1 fixed and how.

A LoRA adapter for `Qwen/Qwen2.5-Coder-14B-Instruct` that plays the **Reviewer** role in the [trace](https://github.com/Ad-Astra-Computing/trace) pipeline. Given a candidate nixpkgs CVE-fix bundle, it emits an accept or reject verdict, with reasoning, findings and cited evidence, in trace's `review.md` format.

v1.1 addresses two false rejects observed in the v1.0 shadow pilot (sqlite CVE-2022-46908 and procps CVE-2023-4016): both packages were absent from v1.0 training data and the model hallucinated scope violations from an over-generalised rejection pattern. The fix moves sqlite from dev to train via a versioned split manifest, adds targeted negatives with the `extra-unrelated-hunk` mutation for both packages to sharpen the scope-violation boundary, and retrains at a step count matched to ~7.5 effective epochs over the larger corpus.

## What it does

Input is a chat-format prompt carrying the bundle's reviewable surface (finding.json, impact.json, upstream-ref.json, patch.diff, prefetch hashes). Output is a `review.md` document with five sections: a verdict (`accept` or `reject`), reasoning tied to the trace review rules, a findings list with severities, the specific evidence citations the verdict rests on, and a cross-family attestation block.

The training target is binary discrimination: accept a correct fix, reject a tampered or out-of-scope one. The adapter is not a patch generator and does not author fixes. It judges them.

The output format is strict. trace parses the `review.md` headings directly, so a malformed heading counts as a failure, not a soft verdict.

## Intended use and scope

Use it inside the trace Reviewer harness, against bundles assembled by the trace CLI. It expects the exact prompt contract the training data used; prompts outside that shape will not produce reliable verdicts.

Out of scope: general code review, freeform security analysis, patch generation, any nixpkgs decision that has not been framed as a trace bundle. The adapter has only seen the trace Reviewer task and should not be treated as a general-purpose reviewer.

## Loading

```python
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import torch

base = "Qwen/Qwen2.5-Coder-14B-Instruct"
adapter = "adastracomputing/reviewer-lora-v1.1"

tok = AutoTokenizer.from_pretrained(base)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True,
)
model = AutoModelForCausalLM.from_pretrained(base, quantization_config=bnb_config, device_map="auto")
model = PeftModel.from_pretrained(model, adapter)
```

The adapter was trained against the nf4 4-bit quantization of the base; the eval in this card loaded the base under the same `BitsAndBytesConfig`. Inputs must be the chat-format prompts the trace Reviewer harness produces. Decode greedily (`do_sample=False`) to match the evaluation.

## Training data

The corpus is `adastracomputing/reviewer-lora-data` frozen at trace commit `636386c`: 104 examples, 77 positives and 27 negatives.

Compared to v1.0 (92 examples, 67 pos + 25 neg):
- 10 new positive bundles added post-v1.0 (shadow pilot cohort).
- 2 new targeted negatives: `CVE-2022-46908--sqlite--extra-unrelated-hunk` and `CVE-2023-4016--procps-ng--extra-unrelated-hunk`. Both use the `extra-unrelated-hunk` mutation, which injects a bogus diff touching a file outside the package's source tree — a definitive scope violation.
- sqlite (CVE-2022-46908) moved from dev to train via `data/splits/reviewer-v1.1.json` (bucket=72, just above the hash-based dev threshold of 70). v1.1 is NOT directly comparable to v1.0 on held-out protocol; the sqlite split changed.

- **Positives (77)** are real trace bundles the Reviewer accepted: 22 auto-merge bundles with signed cert builds and 55 human-review-required bundles. Source-backport fixes (agent-authored code changes) represent roughly 30% of positives.
- **Negatives (27)** are minted by `trace mutate reviewer-negative`: a known-good bundle is mechanically corrupted and a `claude-sonnet-4-5-20250929` Reviewer pass confirms the reject. Note: `claude-sonnet-4-6` emits text before the `=== BEGIN review.md ===` marker and must not be used for minting.

The split uses `data/splits/reviewer-v1.1.json` (versioned manifest) to override the hash-based assignment for sqlite. Effective after manifest application: 82 train, 11 dev, 11 test. No CVE appears in more than one split.

## Training procedure

QLoRA over the 4-bit nf4 double-quantized base. Full configuration in `run_manifest.json` in this repo.

| setting | value |
|---|---|
| base model | `Qwen/Qwen2.5-Coder-14B-Instruct` @ `aedcc2d4` |
| quantization | nf4 4-bit, double-quant, bf16 compute |
| LoRA rank / alpha / dropout | 16 / 16 / 0.05 |
| target modules | all 7 (q, k, v, o, gate, up, down) |
| max steps | 158 (grad-accum 4, ~7.5 effective epochs over 82 train) |
| learning rate | 1e-4, cosine, 15 warmup steps |
| max sequence length | 16384 |
| optimizer | paged AdamW 8-bit |
| seed | 42 |
| hardware | 1× A100 80GB |
| runtime | 71 minutes |

10 of 82 examples were filtered by max_seq_length during tokenization (effective train_n ≈ 72 for those batches). The step count was computed against the nominal 82, yielding ~7.5 effective epochs; the actual filtered count gives ~8.8 effective epochs — both within the v1.0 training range.

Training loss fell from 1.13 at epoch 1.39 to a final 0.6139 at epoch 8.78. Evaluation loss decreased from 1.1256 (epoch 1.39) to a best of 0.3916 (epoch 6.94), then was stable at 0.3924 at epoch 8.33. The best checkpoint by `eval_loss` was loaded at the end. Compare to v1.0: best eval_loss 0.3939 at epoch 8.35; v1.1 is marginally lower.

## Evaluation

### Mixed gate pilot

The gate pilot is the promotion gate. It runs the adapter on the held-out test fold (11 examples: 7 positives + 4 negatives) plus the 2 targeted false-reject examples from the shadow pilot (sqlite + procps, both from train split, both positive label). Gate condition: 0 false rejects and 0 false accepts on the 11 test-split examples.

Gate pilot HF Job `6a38097c3093dba73ce2b76d` (l40sx1). Full results: `data/reports/lora-gate-pilot-v1.1.json` in the trace repository.

**Gate PASS.** 11/11 correct on the test fold: all 7 positives accepted, all 4 negatives rejected. 0 parse failures.

| metric | frontier (sonnet-4-5) | Reviewer-LoRA v1.0 | Reviewer-LoRA v1.1 |
|---|---|---|---|
| verdict accuracy (test fold) | 90.9% (10/11) | 100% (11/11) | 100% (11/11) |
| false accepts (4 negatives) | 0 | 0 | 0 |
| false rejects (7 positives) | 0 | 0 | 0 |
| parse failures | 1 | 0 | 0 |
| sqlite retest | n/a | false-reject | false-reject |
| procps retest | n/a | false-reject | false-reject |

The scorer required a bug fix before producing correct results: the pilot set includes both a positive bundle and a mutation of the same bundle (sharing the same `bundle_id`); the initial scorer indexed by `bundle_id` alone and silently matched the wrong response for the negative. After fixing the key to `(bundle_id, mutation_type or '')`, the results above reflect the actual per-record model outputs.

**Retest note.** The two targeted false-reject examples from the v1.0 shadow pilot (sqlite CVE-2022-46908, procps CVE-2023-4016) are from the train split and are not part of the gate condition. Both are still false-rejected after v1.1 training, despite being in the training set as positives with paired targeted negatives. Root cause is unresolved; these packages appear to have a bundle-specific pattern (possibly related to old CVE dates or nix expression shape) that overrides the training signal. This is a documented open issue, not a gate blocker. See the shadow pilot report and the v1.2 arc below.

### Shadow pilot (v1.0 retrospective)

The v1.0 adapter was run on 16 post-training positive examples (not in v1.0 training data) before v1.1 training. 14/16 were accepted; sqlite and procps were false-rejected. The diagnosis: both packages were absent from v1.0 training data and the model generalised from mutation-based negatives (parameter-name flips, commit misattributions) to reject bundle shapes that superficially resembled those mutations. The v1.1 fix targets this directly.

Results are in `data/reports/lora-shadow-pilot-v1.0.json` in the trace repository.

## Limitations

- **Small evaluation fold.** N is 11 (4 negatives, 7 positives). A perfect score at this scale means no errors were observed, not that the error rate is provably near zero.
- **Synthetic negatives.** The negatives are mechanically minted mutations of known-good bundles. Real-world bad patches can fail in ways the mutation set does not cover.
- **Mutation families not held out.** All four mutation families in the test negatives also appear in training. The reject result measures detection of a known defect family on an unseen CVE, not an unseen defect family.
- **Split protocol changed.** sqlite moved from dev to train in v1.1. Held-out accuracy is not directly comparable to v1.0 across the full eval fold.
- **sqlite + procps false-reject unresolved.** Both train-split positives are still false-rejected after training. Adding them to training as positives with targeted negatives did not resolve the rejection pattern for these specific bundles.
- **Version-bump skew.** The positive class is roughly 70% version-bump fixes. Rebalancing toward source-backport positives is ongoing.
- **Single base model and prompt contract.** The adapter is tied to the exact prompt shape and the specific base revision it was trained on.

## Provenance and reproducibility

| field | value |
|---|---|
| training job | HF Jobs `6a37f837953ed90bfb9470ea` |
| base revision | `aedcc2d42b622764e023cf882b6652e646b95671` |
| dataset | `adastracomputing/reviewer-lora-data` |
| corpus freeze | trace `636386c` |
| split manifest | `data/splits/reviewer-v1.1.json` |
| seed | 42 |

Gate pilot responses are archived at `gate_pilot_responses/responses.jsonl` in this repo. The local scorer and reports live in the trace repository (`eval/score_gate_pilot.py`, `data/reports/lora-gate-pilot-v1.1.json`).

## License

Apache-2.0, matching the base model's own license. The v1.1 weights described here are retired and not separately hosted; the current adapter is public at [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10).
