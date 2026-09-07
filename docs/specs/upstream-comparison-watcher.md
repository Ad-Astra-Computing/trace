# Spec: watch for the nixpkgs fix and score ours against it

- Status: Draft
- Author: Ad Astra Computing Inc
- Date: 7 September 2026
- Related ADRs: none

## Problem

A live-lane bundle is a patch for a flaw nixpkgs has not fixed yet. Its value as
evidence only materialises later, when a nixpkgs maintainer lands their own fix
and the two can be compared. Today that comparison happens by hand, if at all:
someone notices the nixpkgs pull request, finds the matching fork PR, and reads
both. For the historical bundles the comparison was done at build time, because
the human fix already existed. For the live lane nothing does it, so the number
Jason asked for, how often trace's patch matches what nixpkgs eventually ships,
has no source for the cases that matter most.

## Goals

- Detect, for each live-lane fork PR, when NixOS/nixpkgs merges a change that
  addresses the same CVE.
- Fetch that change and score our payload against it with the graders that
  already exist, then record the result beside the bundle and on the fork PR.
- Produce one running table: bundles waiting, bundles compared, and the
  distribution of verdicts.

## Non-goals

- Deciding whether nixpkgs's fix is better. The comparison is descriptive.
- Opening or closing anything on the fork. The PRs are review artifacts and stay
  open.
- Comparing against a version bump as if it were a patch. A bump is recorded as
  its own outcome, `upstream-bumped`, because it is the case where trace's patch
  had no human counterpart to match and the interesting question is whether the
  bump shipped the same fix commit.

## Design

`trace compare watch --fork Ad-Astra-Computing/nixpkgs [--since DATE]` and a
scheduled workflow that runs it.

For each open fork PR on a `trace/<CVE>--<attr>--<bundle_id>` branch, the watcher
reads the bundle's `finding.json` and `upstream-ref.json`, then asks nixpkgs two
questions the screen already knows how to ask: is there a merged PR mentioning
the CVE id, and does the CVE id now appear in the tree. Either answer, when it
becomes true, marks the bundle `landed`.

For a landed bundle it fetches the nixpkgs change. Three shapes are recognised:

1. A patch file added under the package directory: score our payload's inner
   patch against it with `eval/pr_accuracy.score`, which gives change-line
   recall in both directions. Exact match, superset, subset or divergent.
2. A `fetchpatch` pointing at the same upstream commit our bundle names: record
   `same-fix-commit`, since both sides adopted the same upstream change and the
   remaining difference is packaging.
3. A version bump: record `upstream-bumped`, with the fixed version, and check
   whether that release contains the fix commit our bundle cited.

The result is written to `<bundle>/comparison.json` (nixpkgs PR number and merge
date, shape, scores, the upstream commit or version, a UTC timestamp) and posted
as a plain-prose comment on the fork PR. `trace compare report` reads every
`comparison.json` and prints the table: waiting, landed by shape, and for shape 1
the recall distribution. That table is the founding-claim number for the live
lane.

Alternatives rejected: polling from the screen (the screen is for candidates,
not for bundles that already exist); scoring with a model judge first (the
line-recall grader is deterministic and free, and the historical report showed
the model judge disagreeing with it in ways that need a human anyway).

## Acceptance criteria

- [ ] A fork PR whose CVE has no merged nixpkgs PR and no tree mention stays
      `waiting` and gets no comment.
- [ ] A merged nixpkgs PR adding a patch file yields `comparison.json` with recall
      scores from the existing grader and one PR comment.
- [ ] A nixpkgs bump yields `upstream-bumped` with the fixed version and a
      containment check against the cited fix commit.
- [ ] A second run over an already-compared bundle makes no new comment.
- [ ] `compare report` counts waiting and landed bundles and groups landed ones
      by shape.
- [ ] Network calls are injected in tests; the suite makes none.
- [ ] The workflow runs on a schedule with read-only permissions except for
      the PR comment, and pins its actions by SHA.

## Risks and open questions

Detecting "addresses the same CVE" by id is precise but can miss a nixpkgs
change that fixes the flaw without citing the id. That case is recorded as
`waiting` forever unless an operator links it by hand with `--nixpkgs-pr N`. The
scheduled workflow needs a token that can comment on the fork; scope it to that.
