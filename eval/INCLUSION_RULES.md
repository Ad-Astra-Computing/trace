# Eval corpus inclusion rules — FROZEN 2026-04-23

These rules govern which CVEs enter `eval/corpus.json` at `status: "frozen"`.
They are frozen **before** any selection pass begins. Changes after the first
selection commit require a spec amendment and a fresh selection pass with the
new rules applied to the full candidate pool.

The point of freezing is to prevent **easy-case drift**: rules that shift to
accommodate cherry-picked candidates. Once a candidate has been classified,
its fate is decided by these rules, not by convenience.

## Eligibility (must be true of every real corpus entry)

A candidate may be selected for the frozen corpus only if **all** of the
following hold. A candidate failing any of these is rejected, not retained
as a "near miss."

1. **Real, published CVE.** The CVE id exists in NVD, with a publication
   date before the harvest date. No reserved-only or provisional IDs.

2. **Affected at least one nixpkgs attr at some pinned rev.** There must
   exist a specific nixpkgs commit where at least one attr in the corpus's
   target channel (v0: `nixos-unstable`) was affected. The `nixpkgs_rev`
   recorded in the entry is that commit, not today's HEAD.

3. **Ground-truth fix is reachable.** Either (a) an upstream commit or tag
   that fixed the vulnerability, or (b) the nixpkgs commit that resolved
   the CVE in the fork — ideally both. Candidates where "the fix" can only
   be described in prose are rejected.

4. **Harvester can classify all six axes with confidence.** Any axis the
   harvester marks `unclear` disqualifies the candidate. The corpus must
   not be padded with ambiguous entries.

5. **No duplication by pname+version range.** Two CVEs that both affect
   `libfoo` in overlapping version windows are treated as one candidate;
   include the one with cleaner ground-truth fix evidence.

6. **Not withdrawn, not rejected by CVE Numbering Authority.** A CVE whose
   status is `REJECTED` or `WITHDRAWN` at NVD is excluded.

## Axis clarifications (dated, non-amendment)

Added 2026-04-23 after the first harvest surfaced an axis-fit issue. These
clarifications refine how an axis is interpreted during classification; they
do not change the frozen rules.

### `version_bump_complexity`

Means **the complexity of the smallest qualifying upstream release path**
that contains the fix, NOT the complexity of the nixpkgs patch form actually
used historically.

Concretely, for a CVE that nixpkgs addressed via cherry-pick of an upstream
commit while no qualifying upstream release yet existed:

- classify `version_bump_complexity` as whatever the eventual upstream
  release containing the fix would be (usually `patch-release` or
  `point-release`), **and**
- set `expected_upstream_ref_verdict` to
  `ineligible-cherry-pick-required`, **and**
- set `expected_v0_eligibility` to `advisory-only` and
  `expected_bundle_kind` to `advisory-only`.

Rationale: trace v0's model is release/tag integration. The axis describes
the release-path complexity the real trace pipeline would face; the fact
that nixpkgs took a cherry-pick shortcut is captured elsewhere (in the
ineligibility verdict), not double-counted in this axis.

If no release containing the fix exists at all (not even a future one that
can be named), the correct verdict is `ineligible-no-fix-available` or
`ineligible-no-upstream-ref`, and the axis MAY still be filled with the
classifier's judgment of what a hypothetical release would look like,
with `notes` explaining the hypothetical.

## Composition rules (must be true of the corpus as a whole)

Per SPEC §5a and what's already encoded in `tests/eval/test_corpus.py`
composition layer:

- **≥ 50 non-example entries** (`required_size`).
- **No duplicate cve_id.**
- **Every declared axis value is used by at least one non-example entry.**
- **≥ 3 entries per non-trivial bucket** on each axis. See `NON_TRIVIAL_BUCKETS`
  in `tests/eval/test_corpus.py` for the exact buckets-per-axis.
- **≥ 10 entries with `expected_v0_eligibility != "auto-merge-eligible"`** —
  the corpus must exercise the ineligibility paths, not only the happy path.
- **Every real entry has `historical_fix` populated.**

## Selection procedure

1. Harvest ≥ 70 candidate CVEs into `eval/candidates.jsonl` (JSON-lines).
   Each candidate carries the full worksheet; see `eval/HARVESTING.md`.

2. Reject candidates that fail the Eligibility rules above. Move each to
   `eval/rejection-log.jsonl` with a structured reason. No silent deletes.

3. Downselect remaining candidates to exactly 50 that **together satisfy
   the Composition rules**. Downselection that fails composition must be
   re-run from the full pool — not patched by adding candidates after the
   fact.

4. Copy the 50 selected candidates into `eval/corpus.json` as non-example
   entries. Set `status: "frozen"`, `frozen_at: <ISO date>`, commit.

5. From that commit onward, `eval/candidates.jsonl` and
   `eval/rejection-log.jsonl` are append-only historical records. They
   never retroactively change, even if the inclusion rules evolve later.

## What a rule change looks like

A rule change is a spec amendment. It requires:

- A decisions-log entry in `docs/DECISIONS.md` explaining the change.
- An update to this file, dated.
- A new selection pass over the full candidate pool with the new rules.
- The old `eval/corpus.json` is preserved in git history; the new one
  replaces it, with `frozen_at` updated.

There is no in-place patching of the corpus to accommodate edge cases
the old rules missed. This is the load-bearing property of "frozen."
