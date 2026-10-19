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

# Reviewer-LoRA v1.0

v1.0 was the first Reviewer adapter and is retired; its weights are not separately hosted. The current adapter is [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10), public under Apache-2.0. This card is kept for the lineage: what v1.0 did and the pilot result that led to v1.1.

A LoRA adapter for `Qwen/Qwen2.5-Coder-14B-Instruct` that plays the **Reviewer** role in the [trace](https://github.com/Ad-Astra-Computing/trace) pipeline. Given a candidate nixpkgs CVE-fix bundle, it emits an accept or reject verdict, with reasoning, findings and cited evidence, in trace's `review.md` format.

trace produces merge-ready CVE evidence bundles for an agent-owned nixpkgs fork. The Reviewer is the gate: it reads the proposed `patch.diff`, the finding and impact records, the upstream reference and the prefetch hashes, then decides whether the patch is correct, minimal and grounded in the cited fix. This adapter is the first fine-tuned model for that role.

## What it does

Input is a chat-format prompt carrying the bundle's reviewable surface (finding.json, impact.json, upstream-ref.json, patch.diff, prefetch hashes). Output is a `review.md` document with five sections: a verdict (`accept` or `reject`), reasoning tied to the trace review rules, a findings list with severities, the specific evidence citations the verdict rests on, and a cross-family attestation block.

The training target is binary discrimination: accept a correct fix, reject a tampered or out-of-scope one. The adapter is not a patch generator and does not author fixes. It judges them.

The output format is strict. trace parses the `review.md` headings directly, so a malformed heading counts as a failure, not a soft verdict.

## Intended use and scope

Use it inside the trace Reviewer harness, against bundles assembled by the trace CLI. It expects the exact prompt contract the training data used; prompts outside that shape will not produce reliable verdicts.

Out of scope: general code review, freeform security analysis, patch generation, any nixpkgs decision that has not been framed as a trace bundle. The adapter has only seen the trace Reviewer task and should not be treated as a general-purpose reviewer.

## Loading

```python
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base = "Qwen/Qwen2.5-Coder-14B-Instruct"
adapter = "adastracomputing/reviewer-lora-v1.0"

tok = AutoTokenizer.from_pretrained(base)
model = AutoModelForCausalLM.from_pretrained(base, device_map="auto")
model = PeftModel.from_pretrained(model, adapter)
```

The adapter was trained against the nf4 4-bit quantization of the base; the eval in this card loaded the base under the same `BitsAndBytesConfig`. Inputs must be the chat-format prompts the trace Reviewer harness produces. Decode greedily (`do_sample=False`) to match the evaluation.

## Training data

The corpus is `adastracomputing/reviewer-lora-data` at commit `f6493f5`, frozen at trace `e70b3ff`: 92 examples, 67 positives and 25 negatives.

- **Positives (67)** are real trace bundles the Reviewer accepted: 22 auto-merge bundles gated on a signed cert build (patch applied and built on x86_64-linux, then Steward-signed) and 45 human-review-required bundles where acceptance rests on the Reviewer verdict. The positive class currently leans toward version-bump fixes (roughly 70%), with 20 source-backport fixes where the agent authored the code change rather than bumping a version.
- **Negatives (25)** are minted by `trace mutate reviewer-negative`: a known-good bundle is mechanically corrupted (an unrelated hunk injected, the target version set wrong, the patch made to touch an unrelated file) and a real Reviewer pass confirms the reject. The negative therefore carries a genuine rejection with grounded reasoning, not a synthetic label.

The split is grouped by `split_family` (the package attribute path): 69 train, 12 dev, 11 test. No CVE appears in more than one split. That reduces direct bundle recall; the limitations section describes the distribution overlap that remains through shared mutation families.

## Training procedure

QLoRA over the 4-bit nf4 double-quantized base. The full configuration is recorded in `run_manifest.json` in this repo.

| setting | value |
|---|---|
| base model | `Qwen/Qwen2.5-Coder-14B-Instruct` @ `aedcc2d4` |
| quantization | nf4 4-bit, double-quant, bf16 compute |
| LoRA rank / alpha / dropout | 16 / 16 / 0.05 |
| target modules | all 7 (q, k, v, o, gate, up, down) |
| max steps | 150 (grad-accum 4, ~8.35 epochs over 69 train) |
| learning rate | 1e-4, cosine, 15 warmup steps |
| max sequence length | 16384 |
| optimizer | paged AdamW 8-bit |
| seed | 42 |
| hardware | 1× A100 80GB |
| runtime | 65 minutes |

Training loss fell from 1.25 at step 5 to a 0.627 mean. Evaluation loss decreased monotonically across the six eval points (0.4105 to a 0.3939 best at epoch 8.35), and the best checkpoint by `eval_loss` was loaded at the end. No loss spike was observed in the logged run.

## Evaluation

Verdicts were generated greedily (temperature 0) on the held-out test fold and scored with the same scoring function used for the frontier baseline, so the comparison is like for like. The frontier baseline is `claude-sonnet-4-5-20250929` on the identical fold.

| metric | frontier (sonnet-4-5) | Reviewer-LoRA v1.0 |
|---|---|---|
| verdict accuracy | 90.9% (10 of 11) | 100% (11 of 11) |
| false accepts (on 4 negatives) | 0 | 0 |
| false rejects (on 7 positives) | 0 | 0 |
| parse failures | 1 | 0 |
| schema-valid rate | 90.9% | 100% |

The adapter accepted all 7 correct patches and rejected all 4 tampered ones. The measured accuracy difference comes from parse reliability: sonnet-4-5 produced one unparsable response, while the adapter produced 11 schema-valid responses. Read this as a clean result on a frozen 11-example fold, not as a broad capability claim. See the limitations below for what the held-out negatives do and do not establish.

Four CVEs appear in the fold as both a clean positive and a mutated negative (CVE-2025-26625, CVE-2025-12888, CVE-2025-2337, CVE-2024-8176). The adapter accepted the correct patch and rejected the tampered patch of the same CVE in every case, which is direct evidence that it discriminates on patch correctness rather than on the package or CVE identity. The four negatives span four distinct mutation types and all were caught.

## Limitations

- **Small evaluation fold.** N is 11 (4 negatives, 7 positives). A perfect score at this scale means no errors were observed, not that the error rate is provably near zero. Treat it as a strong early signal, not a tight bound.
- **Synthetic negatives.** The negatives are mechanically minted mutations of known-good bundles. Real-world bad patches can fail in ways the mutation set does not cover, so reject performance on natural failures is untested.
- **Defect families are not held out.** The CVE-level split is clean (no test CVE appears in training), but all four mutation families in the test negatives also appear in training. The reject result therefore measures detection of a known defect family on an unseen CVE, not detection of an unseen defect family. A stronger evaluation would hold out an entire mutation family.
- **False-accept estimate is wide.** Zero false accepts were observed, but on only four held-out negatives the uncertainty on that rate is large. This is "no false accepts seen at this scale," not a solved risk.
- **Version-bump skew in the positives.** The positive class is roughly 70% version-bump fixes. The held-out result shows the shortcut did not win, but rebalancing toward more source-backport positives is the planned next step to widen the non-trivial signal.
- **Single base model and prompt contract.** The adapter is tied to the exact prompt shape and the specific base revision it was trained on. It will not transfer to a different prompt format or a different base without retraining.

## Provenance and reproducibility

| field | value |
|---|---|
| training job | HF Jobs `6a337b28fb114ff24a388b03` (eval), `6a3369b75ff0a6cf94fa0d22` (train) |
| base revision | `aedcc2d42b622764e023cf882b6652e646b95671` |
| dataset | `adastracomputing/reviewer-lora-data` @ `f6493f5` |
| corpus freeze | trace `e70b3ff` |
| trace commit | `8453ca7` |
| seed | 42 |

Held-out responses are archived at `eval/responses.jsonl` in this repo. The local scorer and the comparison report live in the trace repository (`eval/score_lora_responses.py`, `data/reports/lora-eval-v1.0.json`).

## License

Apache-2.0, matching the base model's own license. The v1.0 weights described here are retired and not separately hosted; the current adapter is public at [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10).
