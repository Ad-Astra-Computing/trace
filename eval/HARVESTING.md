# Eval corpus harvesting workflow

The inclusion rules at `INCLUSION_RULES.md` are frozen. This file describes
the **process** of collecting candidates and making the selection pass.

## Artifacts

- `eval/candidates.jsonl` — one JSON object per line, one per candidate CVE.
  Populated during harvesting. Append-only. Schema:
  `policy/eval-candidate-schema.json`.
- `eval/rejection-log.jsonl` — one JSON object per line, one per rejected
  candidate with a structured reason. Append-only. Schema:
  `policy/eval-rejection-schema.json`.
- `eval/corpus.json` — the final selection. Starts as `status: "seed"` with
  only example entries; flips to `status: "frozen"` once 50 real entries are
  chosen.

## Worksheet (required fields per candidate)

Every line in `candidates.jsonl` carries:

| Field | Notes |
|---|---|
| `cve_id` | Real published CVE. |
| `nixpkgs_rev` | 40-hex commit where the vulnerable version existed. |
| `affected_attrs` | Non-empty list of attr paths. |
| `historical_fix` | `{upstream_repo_url?, upstream_commit_sha?, upstream_tag_or_release?, nixpkgs_fix_commit_sha?}` — at least one present. |
| `axes.mapping_difficulty` | `easy` / `medium` / `ambiguous`. |
| `axes.version_bump_complexity` | `patch-release` / `point-release` / `multi-release` / `major-jump`. |
| `axes.passthru_tests` | `yes` / `minimal` / `none`. |
| `axes.reproducibility` | `straightforward` / `config-sensitive` / `DoS-shaped` / `crypto-shaped` / `parser-heavy` / `kernel-adjacent` / `impractical`. |
| `axes.rebuild_closure_size` | `<50` / `50-500` / `500-5000` / `>5000`. |
| `axes.human_decision_difficulty` | `trivial` / `routine` / `contentious`. |
| `expected_v0_eligibility` | `auto-merge-eligible` / `requires-human-review` / `advisory-only`. |
| `expected_bundle_kind` | `auto-merge` / `human-review-required` / `advisory-only`. Must be consistent with `expected_v0_eligibility`. |
| `expected_upstream_ref_verdict` | From the upstream-ref-schema enum. |
| `harvested_at` | ISO-8601 date-time. |
| `harvested_by` | Pseudonymous identifier of the harvester. |
| `candidate_source` | Where the harvester first encountered this CVE. Enum: `nixpkgs-git-history`, `ghsa`, `nvd`, `vulnpatch`, `osv`, `nixpkgs-cve-tracker`, `manual`. Informational only — not a policy input. Later lets reviewers see whether the pool was drawn broadly or narrowly. |
| `notes` | Optional free-form. |

## Rejection log (required fields per rejection)

Every line in `rejection-log.jsonl`:

| Field | Notes |
|---|---|
| `cve_id` | |
| `rejected_at` | ISO-8601 date-time. |
| `rejected_by` | |
| `reason` | One of the enum values in `policy/eval-rejection-schema.json`. |
| `notes` | Free-form. Strongly recommended for `other` and for borderline rejections. |

## Process

1. **Harvest.** Collect 70–90 candidate CVEs per the worksheet above. Draw
   from sources like nixpkgs git history (`git log --grep CVE-`), the
   nixpkgs CVE tracker, NVD export filtered by nixpkgs-affected packages,
   and the GHSA advisory feed. Each candidate is one JSON line in
   `candidates.jsonl`.

2. **Apply eligibility rules.** For each candidate, check the six rules in
   `INCLUSION_RULES.md` § Eligibility. Failing candidates move to
   `rejection-log.jsonl` with a structured reason. No silent deletions.

3. **Downselect for composition.** From the surviving candidates, choose
   exactly 50 that together satisfy the composition rules. If a valid
   selection does not exist, harvest more candidates and retry — do not
   weaken the composition rules.

4. **Freeze.** Copy the 50 selected entries into `eval/corpus.json` as
   real entries (`is_example: false`). Flip `status` to `"frozen"` and
   set `frozen_at` to the ISO date of the commit. Seed/example entries
   stay in place during transition; they do not count toward the 50.

5. **Verify.** Run `TRACE_REQUIRE_FULL_CORPUS=1 pytest tests/eval` — every
   composition rule must pass. If any rule fails, undo and return to step 3.

6. **Commit.** The freeze commit includes `corpus.json`, `candidates.jsonl`,
   `rejection-log.jsonl`, and is the canonical point in time. Future
   candidates or rejections append; they do not rewrite.

## Source-truth verification (mandatory)

Every candidate's `historical_fix.nixpkgs_fix_commit_sha` MUST be verified
against **upstream** `NixOS/nixpkgs` master before the candidate is
accepted. A local nixpkgs checkout is not sufficient — it can contain:

- commits from the harvester's own PR branches
- commits from `nixpkgs-review/0` (fetched by the `nixpkgs-review` tool)
- stale `origin/master` if the local clone hasn't been fetched recently
- commits from the nixos-unstable / nixos-24.11 release branches that have
  not (yet) been merged into master

Any of those will pass a local `git log` search but will not be on the
real canonical master. The result is a candidate whose `nixpkgs_fix_commit_sha`
cannot be reproduced by an external reviewer.

### Verification procedure

For each candidate SHA `<sha>`, the harvester runs:

    gh api "repos/NixOS/nixpkgs/compare/master...<sha>" --jq '.status'

The commit is accepted iff the status is `behind` or `identical`. Reject
on `ahead`, `diverged`, or any other value. If the candidate was originally
from a PR-branch SHA, use GitHub's commit search to find the actual merge
commit on master and substitute:

    gh api -X GET "search/commits" -f q="repo:NixOS/nixpkgs <package> <version>"

Then record the MASTER commit's SHA (not the PR-branch SHA) in the
candidate. Use that master commit's parent as `nixpkgs_rev`.

### Calibration note on GitHub compare status

The `compare/BASE...HEAD` endpoint returns a `status` field whose values
read counter-intuitively in this direction of use:

- `identical` — BASE and HEAD are the same commit.
- `behind` — BASE is "behind" HEAD in the graph sense, which in this
  direction means **HEAD is an ancestor of BASE**. I.e. HEAD (the
  candidate) IS on master. **This is the success case for our use.**
- `ahead` — BASE is ahead of HEAD, meaning HEAD is a descendant of BASE.
  Unusual for our use; treat as reject.
- `diverged` — both sides have unique commits; candidate is on a different
  branch. Reject.

The wording is easy to misread as "behind = not ready / not in master."
Empirically verify: `compare/master...master^1` returns `behind`. The
calibration check is the authority, not intuition.

## Honesty anchors

- The rejection log exists so that a future reviewer asking "was this
  corpus cherry-picked?" gets an answer from data, not memory. Every
  excluded CVE has a documented reason.
- `candidates.jsonl` is not a curated list. It includes candidates that
  ended up rejected. The ratio of selected to rejected is itself a
  signal about harvesting rigor.
- Axis classifications must be defensible. If a harvester finds themselves
  flipping an axis value to make a candidate fit a bucket, the candidate
  should be rejected with `reason: "classification-forced-to-fit"`.
