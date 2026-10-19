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
---

# Reviewer-LoRA training data

Published at [huggingface.co/datasets/adastracomputing/reviewer-lora-data](https://huggingface.co/datasets/adastracomputing/reviewer-lora-data), under Apache-2.0.

Instruction-tuning data for the **Reviewer** role in the [trace](https://github.com/Ad-Astra-Computing/trace) pipeline. Each example is a single chat-format turn: trace presents a candidate nixpkgs CVE-fix bundle, and the assistant answers with an accept or reject verdict in trace's `review.md` format.

trace builds merge-ready CVE evidence bundles for an agent-owned nixpkgs fork. The Reviewer decides whether a proposed `patch.diff` is correct, minimal and grounded in the cited upstream fix. This dataset is the supervised signal for fine-tuning that judgment. It trained the first Reviewer-LoRA adapter and every version since, through the current [`reviewer-lora-v1.10`](https://huggingface.co/adastracomputing/reviewer-lora-v1.10).

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

## License

Apache-2.0.
