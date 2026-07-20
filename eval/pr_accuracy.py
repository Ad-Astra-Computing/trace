"""Corpus PR-accuracy: does trace's model-authored fix match the upstream fix?

The fork PRs trace opens are accuracy-comparison artifacts (NOT merge candidates):
each carries a model-AUTHORED source patch, and the bundle also carries the real
upstream fix as ground truth (`upstream-fix.patch`). This harness scores, across the
whole corpus, how closely the authored fix reproduces the upstream fix — the
"verify this actually works" gate before trace is pointed at live vulnerabilities.

Scope: bundles that are source-backports (patch.diff embeds a new `*.patch` file — the
model's authored source fix) AND carry `upstream-fix.patch`. Version-bump bundles
(nix-only patch.diff) are excluded: a bump is not an authored code change (the nix CI
bot already does bumps), so there is no fix-shape to score.

The metric is the graded ladder from the authoring investigation, applied to the
CHANGED source lines only (context + line numbers ignored, whitespace-normalized):
  - removed_recall : fraction of upstream's removed (`-`) lines the authored fix removes
  - added_recall   : fraction of upstream's added   (`+`) lines the authored fix adds
  - exact          : authored added+removed line-sets == upstream's (order/context-free)
Aggregate reports mean recalls + exact-match count over the scorable corpus.

Usage:
  python3 eval/pr_accuracy.py                         # score all scorable bundles
  python3 eval/pr_accuracy.py --traces-root traces/example --out data/reports/pr-accuracy.json
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def extract_authored_patch(patch_diff: str) -> str | None:
    """Return the embedded `*.patch` new-file body from a bundle patch.diff.

    A source-backport patch.diff adds the authored fix as a new `*.patch` file, so
    that file's body is `+`-prefixed inside the outer diff. We locate the `.patch`
    new-file section, skip its outer `@@` header, and strip exactly one leading `+`
    from each body line to recover the inner unified diff (the authored source fix).
    Returns None if patch.diff embeds no `*.patch` file (a nix-only/bump diff).
    """
    lines = patch_diff.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        # find the outer +++ header pointing at a *.patch file
        m = re.match(r"^\+\+\+ b/.*\.patch$", lines[i])
        if not m:
            i += 1
            continue
        # skip forward to the outer @@ hunk header, then collect the body
        j = i + 1
        while j < n and not lines[j].startswith("@@"):
            # a non-@@, non-+++ line before the hunk header means this isn't a
            # clean new-file add; bail on this candidate.
            if lines[j].startswith("diff --git"):
                break
            j += 1
        if j >= n or not lines[j].startswith("@@"):
            i += 1
            continue
        body: list[str] = []
        k = j + 1
        while k < n and not lines[k].startswith("diff --git"):
            ln = lines[k]
            if ln.startswith("+"):
                body.append(ln[1:])
            elif ln.strip() == "" or ln.startswith("\\"):
                body.append(ln)  # blank / "\ No newline at end of file"
            else:
                break  # left the all-additions new-file body
            k += 1
        text = "\n".join(body).strip("\n")
        return text or None
    return None


def parse_change_lines(unified_diff: str) -> tuple[list[str], list[str]]:
    """Split a unified diff into (removed, added) content lines, whitespace-normalized.

    Diff/hunk/file headers are skipped; only real `-`/`+` payload lines are kept, so
    two diffs that make the same change at different line numbers / with different
    context compare equal.
    """
    removed, added = [], []
    for ln in unified_diff.splitlines():
        if ln.startswith(("+++", "---", "diff ", "index ", "@@", "\\")):
            continue
        if ln.startswith("-"):
            removed.append(_norm(ln[1:]))
        elif ln.startswith("+"):
            added.append(_norm(ln[1:]))
    return [x for x in removed if x], [x for x in added if x]


def _recall(ref: list[str], got: list[str]) -> float:
    if not ref:
        return 1.0
    gotset = set(got)
    return sum(1 for x in ref if x in gotset) / len(ref)


def score(authored_diff: str, upstream_diff: str) -> dict:
    a_rm, a_add = parse_change_lines(authored_diff)
    u_rm, u_add = parse_change_lines(upstream_diff)
    removed_recall = _recall(u_rm, a_rm)
    added_recall = _recall(u_add, a_add)
    exact = set(a_rm) == set(u_rm) and set(a_add) == set(u_add) and bool(u_add or u_rm)
    return {
        "removed_recall": round(removed_recall, 4),
        "added_recall": round(added_recall, 4),
        "exact": exact,
        "upstream_removed": len(u_rm),
        "upstream_added": len(u_add),
    }


def score_bundle(bundle_dir: Path) -> dict | None:
    """Score one bundle; return None if it is not a scorable source-backport."""
    pd = bundle_dir / "patch.diff"
    gt = bundle_dir / "upstream-fix.patch"
    if not pd.exists() or not gt.exists():
        return None
    authored = extract_authored_patch(pd.read_text())
    if authored is None:
        return None  # nix-only / version-bump: nothing authored to score
    s = score(authored, gt.read_text())
    s["bundle"] = bundle_dir.name
    return s


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traces-root", type=Path, default=ROOT / "traces" / "example")
    ap.add_argument("--out", type=Path, default=ROOT / "data/reports/pr-accuracy.json")
    ap.add_argument("--only", help="restrict to bundle dirs containing this substring")
    args = ap.parse_args()

    results = []
    for d in sorted(p for p in args.traces_root.iterdir() if p.is_dir()):
        if args.only and args.only not in d.name:
            continue
        r = score_bundle(d)
        if r is not None:
            results.append(r)

    n = len(results)
    if not n:
        print("no scorable source-backport bundles found")
        return
    mean_add = round(sum(r["added_recall"] for r in results) / n, 4)
    mean_rm = round(sum(r["removed_recall"] for r in results) / n, 4)
    exact_n = sum(1 for r in results if r["exact"])
    add_full = sum(1 for r in results if r["added_recall"] >= 0.999)

    print(f"PR accuracy — {n} source-backport bundles scored vs upstream ground truth")
    print(f"  exact fix match     : {exact_n}/{n} ({round(100*exact_n/n)}%)")
    print(f"  full added-line recall: {add_full}/{n} ({round(100*add_full/n)}%)")
    print(f"  mean added_recall   : {mean_add}")
    print(f"  mean removed_recall : {mean_rm}")
    print("  imperfect fixes (added_recall < 1.0):")
    for r in sorted(results, key=lambda x: x["added_recall"]):
        if r["added_recall"] < 0.999:
            print(f"    {r['bundle']:52} add={r['added_recall']} rm={r['removed_recall']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "scored": n, "exact": exact_n, "full_added_recall": add_full,
        "mean_added_recall": mean_add, "mean_removed_recall": mean_rm,
        "results": results,
    }, indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
