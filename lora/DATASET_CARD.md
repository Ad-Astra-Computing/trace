---
license: apache-2.0
task_categories:
  - text-generation
language:
  - en
tags:
  - code-review
  - nixpkgs
  - security
  - cve
  - instruction-tuning
size_categories:
  - n<1K
configs:
  - config_name: default
    data_files:
      - split: train
        path: reviewer.train.jsonl
      - split: dev
        path: reviewer.dev.jsonl
      - split: test
        path: reviewer.test.jsonl
  - config_name: v1.10
    data_files:
      - split: train
        path: reviewer-v1.10.train.jsonl
      - split: dev
        path: reviewer-v1.10.dev.jsonl
---

# Reviewer-LoRA training data

Published at [huggingface.co/datasets/adastracomputing/reviewer-lora-data](https://huggingface.co/datasets/adastracomputing/reviewer-lora-data), under Apache-2.0.

Instruction-tuning data for the **Reviewer** role in the [trace](https://github.com/Ad-Astra-Computing/trace) pipeline. Each example is a single chat-format turn: trace presents a candidate nixpkgs CVE-fix bundle, and the assistant answers with an accept or reject verdict in trace's `review.md` format.

trace builds merge-ready CVE evidence bundles for an agent-owned nixpkgs fork. The Reviewer decides whether a proposed `patch.diff` is correct, minimal and grounded in the cited upstream fix. This dataset is the supervised signal for fine-tuning that judgment. The default config below (the `e70b3ff` freeze) trained Reviewer-LoRA v1.0 through v1.5. From v1.6 onward, each adapter version trained on its own frozen, larger file pair as the corpus grew; the current [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10) trained on the `v1.10` config below. See "Other files in this repository" for the rest of the lineage.

## Composition

92 examples, frozen at trace `e70b3ff`.

| split | examples |
|---|---|
| train | 69 |
| dev | 12 |
| test | 11 |
| total | 92 |

By label: 67 positives (accept) and 25 negatives (reject).

## Where the examples come from

**Positives (67).** Real trace bundles the Reviewer accepted: 22 auto-merge bundles gated on a signed cert build (patch applied and built on x86_64-linux, then Steward-signed) and 45 human-review-required bundles where acceptance rests on the Reviewer verdict. The assistant turn is the actual Reviewer verdict recorded during that bundle's run. The positive class currently leans toward version-bump fixes, with 20 source-backport fixes where the agent authored the code change.

**Negatives (25).** Minted by `trace mutate reviewer-negative`. A known-good bundle is mechanically corrupted in one specific way, then a real Reviewer pass runs against the corrupted bundle and confirms the reject. The recorded assistant turn is that genuine rejection, with reasoning grounded in the injected defect, not a synthetic label. The eight mutation types are:

| mutation type | count |
|---|---|
| wrong-target-version | 6 |
| extra-unrelated-hunk | 6 |
| rationale-cites-wrong-version | 4 |
| patch-touches-unrelated-file | 3 |
| wrong-src-hash | 3 |
| hash-from-other-bundle | 1 |
| rationale-cites-wrong-hash | 1 |
| version-without-hash | 1 |

## Record schema

Each line is a JSON object with these fields:

- `messages`: the chat turns (`system`, `user`, `assistant`). The user turn carries the reviewable surface (finding.json, impact.json, upstream-ref.json, patch.diff, prefetch hashes). The assistant turn is the target `review.md`.
- `label`: `positive` or `negative`.
- `split`: `train`, `dev` or `test`.
- `scope` and `eligibility_for_training`: trace's gating metadata for whether the example is eligible.
- `provenance`: the bundle's lineage, including `bundle_id`, `base_bundle_id` (the source bundle for a mutated negative), `cve_id`, `attr_path`, `kind` (`human-review-required` or `auto-merge`), `has_cert_build`, `steward_signed`, the `patcher_model_id` and `reviewer_model_id` that produced the original run, the `reviewer_prompt_sha`, `mutation_type` and `negative_source` for negatives, and `split_family`.

## How the split was made

The split is grouped by `split_family` (the package attribute path), so every CVE and its mutated negatives land entirely in one split. No CVE appears in both train and test in any form. This is deliberate: it makes any evaluation on the test split a generalization measurement rather than recall of a seen bundle. On the v1.0 eval, all 11 test CVE-ids had zero occurrences in train.

`reviewer.test.jsonl` carries only the `messages` field, unlike `reviewer.train.jsonl` and `reviewer.dev.jsonl`, which keep full provenance: the export tool that wrote it is built never to emit split, label or provenance alongside a model-facing prompt, by design, so there is no richer version of this file to restore. Each row's CVE id is still recoverable from the embedded `finding.json` in the user turn, which is how the "zero occurrences in train" check above was verified.

## Intended use and limitations

The data trains and evaluates the trace Reviewer. It is tied to trace's prompt contract and is not a general code-review corpus.

- **Small.** 92 examples, 11 of them held out. Useful for a focused role adapter, not for broad capability claims.
- **Synthetic negatives.** The 25 negatives are mechanical mutations. They cover a defined defect set and do not represent the full distribution of real-world bad patches.
- **Mutation families are shared across splits.** The split holds out CVEs, not defect types. Every mutation family present in the test negatives also appears in train. An evaluation on this split measures detection of a known defect family on an unseen CVE, not detection of an unseen defect family. A harder split would hold out a whole mutation family.
- **Positive-class skew.** Roughly 70% of the positives are version-bump fixes. Rebalancing toward more source-backport positives is the planned next step.
- **Model-authored verdicts.** The assistant turns were produced by the trace Reviewer agent during cert runs, then gated. They reflect that agent's reasoning and the trace review rules in force at freeze time.

## Provenance

| field | value |
|---|---|
| corpus freeze | trace `e70b3ff` |
| produced by | trace export and mutation tooling (`trace export reviewer`, `trace mutate reviewer-negative`) |
| original reviewer model | `claude-sonnet-4-5-20250929` |
| schema | recorded per record in `schema_version` |

## Other files in this repository

Each Reviewer-LoRA version past v1.5 trained on its own frozen, larger train/dev pair as the corpus grew, uploaded by that version's `lora/submit_hf_job_v1.N.sh` in the trace repository. Kept here as the training-provenance record for each adapter's own model card, not superseded data:

| files | train / dev rows | trained |
|---|---|---|
| `reviewer-v1.6.train/dev.jsonl` | 88 / 10 | Reviewer-LoRA v1.6 |
| `reviewer-v1.7.train/dev.jsonl` | 92 / 10 | Reviewer-LoRA v1.7 |
| `reviewer-v1.8.train/dev.jsonl` | 97 / 10 | Reviewer-LoRA v1.8 |
| `reviewer-v1.9.train/dev.jsonl` | 105 / 10 | Reviewer-LoRA v1.9 |
| `reviewer-v1.10.train/dev.jsonl` | 107 / 10 | Reviewer-LoRA v1.10 (current), also the `v1.10` config above |
| `reviewer-v1.11.train/dev.jsonl` | 113 / 10 | Reviewer-LoRA v1.11 (draft) |

Inference-only inputs, not training data: `gate-pilot.jsonl` (45 rows) and `reviewer-v1.11-gate-pilot-only.jsonl` (20 rows) are gate-pilot evaluation prompts; `shadow-pilot.jsonl` (16 rows) and `reviewer-v1.11-compound-guard-probe-only.jsonl` (25 rows) are held-out probe prompts for a specific regression check.

`train.jsonl` (111 rows) is an earlier, unsplit export with no remaining consumer; kept for history rather than deleted, since Hugging Face repositories are themselves git history.

## License

Apache-2.0.
