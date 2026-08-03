# Reserved hard positives — DO NOT export into Reviewer training

Authored hard compound-guard positives (equivalence-proven, same tooling and
provenance as `traces/positives-reorg/`) that are **deliberately held out of the
training corpus** because their base family backs a held-out probe family.

## The rule

Hard positives are TRAIN data. Probe families must be held out of TRAIN. So:

- Hard positives → author from families **already in the frozen training corpus**.
- Families **absent** from that corpus that carry a real multi-conjunct guard →
  reserved for the held-out probe, and never promoted to training.

Promoting a hard positive whose family backs a probe family would consume, as a
train row, the very family the probe measures — a family-level leak that
invalidates the held-out measurement while every individual artifact still looks
correct.

## Authoritative membership check — READ THIS BEFORE ALLOCATING A FAMILY

Check membership against the **frozen corpus report**:

    data/reports/reviewer-corpus-2026-07-27-freeze.json   ->  eligible_examples[].attr_path

**Not** `exports/reviewer-v1.10/reviewer.train.jsonl`. Those two disagree, and
using the export produced a wrong allocation on 2026-08-03 (see DECISIONS
2026-08-03 "family-allocation rule CORRECTED"): `jq` and `libarchive` are in the
frozen corpus and are therefore legitimate *training* families, while only
`krb5` is genuinely fresh.

Note the normalizer strips **all** digit runs, not just a trailing version
suffix: `krb5` normalizes to `krb`, `ffmpeg_5` to `ffmpeg`. Compare normalized
forms on both sides or the check silently passes.

## Current allocation

| family | in frozen corpus | role |
|---|---|---|
| `krb5` (`krb`) | no | **probe family** — hard positive reserved here |
| `jq` | yes | training family — positive lives in `traces/positives-reorg/` |
| `libarchive` | yes | training family — positive lives in `traces/positives-reorg/` |
| `libwebp`, `ffmpeg` | no | probe families (original two) |
| `fig2dev` (`figdev`) | no | candidate probe family, bundle still in staging |

## Status

Inert by construction: minting deletes `review.md`, and
`tools/trace_cli/export.py` requires a freshly parsed `accept` review before a
reorg bundle becomes training-eligible. So nothing here can enter the corpus
without a deliberate Reviewer pass — which must not happen while the family
backs a probe.

Equivalence proofs and hardness rationales stay valid and under test:
`tests/schema/test_compound_guard_positives.py` globs this directory too, so
moving a bundle between train-eligible and reserved never drops its proof from
coverage. If a family later leaves the probe, its bundle can be promoted back
unchanged.
