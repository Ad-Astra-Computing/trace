# Reserved hard positives — DO NOT export into Reviewer training

These are authored hard compound-guard positives (equivalence-proven, same
provenance and tooling as `traces/positives-reorg/`) that are **deliberately
held out of the training corpus**.

## Why

Hard positives are training data. Probe families must be held out of training.
`krb5`, `jq` and `libarchive` are **fresh compound-guard families that are not
in the Reviewer train split** — and fresh non-train compound-guard families are
the scarcest resource in the v1.11 experiment. A scan of `traces/example/` found
**zero** eligible compound-guard families that are neither already in train nor
already probe families, so the held-out probe can only be widened using these.

Promoting them to training would consume, as train rows, exactly the families the
probe needs — a family-level leak that would silently invalidate the held-out
measurement. Hard positives do not need scarce families: they may legitimately be
authored from any of the 57 families **already** in the train split.

## Allocation rule (adopted 2026-08-03)

- Hard positives → author ONLY from families already in the Reviewer train split.
- Fresh non-train compound-guard families → reserved for the held-out probe.

## Status

Inert by construction: `_stage_copy` deletes `review.md` on mint, and
`tools/trace_cli/export.py` requires a freshly parsed `accept` review before a
reorg bundle becomes training-eligible. They therefore cannot enter the corpus
until someone runs a Reviewer pass over them — which for these three must NOT
happen while they back probe families.

Their equivalence proofs and hardness rationales remain valid and are preserved
in each bundle's `reorg.json`; if a family is later dropped from the probe, its
bundle here can be promoted back to `traces/positives-reorg/` unchanged.
