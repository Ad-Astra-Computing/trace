"""`trace compare watch`: notice when nixpkgs lands a fix for a live-lane bundle,
score our payload against it and record the result.

A live-lane bundle is a patch for a flaw nixpkgs has not fixed yet, so its value
as evidence appears later, when a maintainer lands their own change. This is the
step that turns "we patched it first" into a measured comparison. Every network
call is injected so the logic is testable without one.

See docs/specs/upstream-comparison-watcher.md.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_BRANCH_RE = re.compile(r"^trace/(CVE-\d{4}-\d{4,})--(.+?)--([0-9a-f]{16})$")
_VERSION_RE = re.compile(r'^([+-])\s*version\s*=\s*"([^"]+)"\s*;', re.M)
_PATCH_FILE_RE = re.compile(r"\.(patch|diff)$")


def parse_fork_branch(name: str) -> tuple[str, str, str] | None:
    m = _BRANCH_RE.match(name or "")
    return (m.group(1), m.group(2), m.group(3)) if m else None


def classify_change(files: list[dict], *, fix_shas: list[str], current_version: str) -> dict:
    """Which of the three recognised shapes a merged nixpkgs change took."""
    patch_files = [f["filename"] for f in files if _PATCH_FILE_RE.search(f.get("filename", ""))
                   and f.get("status") in (None, "added", "modified")]
    if patch_files:
        return {"shape": "patch-file", "patch_files": patch_files}
    joined = "\n".join(f.get("patch") or "" for f in files)
    for sha in fix_shas:
        if sha and (sha in joined or sha[:12] in joined):
            return {"shape": "same-fix-commit", "commit_sha": sha}
    removed = added = None
    for sign, ver in _VERSION_RE.findall(joined):
        if sign == "-":
            removed = ver
        else:
            added = ver
    if added and added != (removed or current_version):
        return {"shape": "upstream-bumped", "fixed_version": added, "previous_version": removed or current_version}
    return {"shape": "other"}


def _authored_inner_patch(bundle_dir: Path) -> str | None:
    from eval.pr_accuracy import extract_authored_patch

    p = bundle_dir / "patch.diff"
    return extract_authored_patch(p.read_text()) if p.is_file() else None


def _score_both_ways(authored: str, upstream: str) -> dict:
    """Recall in both directions.

    `added_recall` and `removed_recall` (from eval.pr_accuracy) ask how much of
    nixpkgs's change ours contains, which penalises a minimal payload for
    omitting their test and changelog lines. `payload_*_recall` asks how much of
    ours is in theirs, which is the question of whether we fixed the same thing.
    """
    from eval.pr_accuracy import parse_change_lines, score

    s = score(authored, upstream)
    a_rm, a_add = parse_change_lines(authored)
    u_rm, u_add = parse_change_lines(upstream)
    def recall(ref, got):
        return 1.0 if not ref else round(sum(1 for x in ref if x in set(got)) / len(ref), 4)
    s["payload_removed_recall"] = recall(a_rm, u_rm)
    s["payload_added_recall"] = recall(a_add, u_add)
    return s


def compare_bundle(bundle_dir: Path, change: dict, *, fetch_file: Callable[[int, str], str]) -> dict:
    """Score the bundle against one merged nixpkgs change and write comparison.json."""
    from eval.pr_accuracy import score

    ref = json.loads((bundle_dir / "upstream-ref.json").read_text()) if (bundle_dir / "upstream-ref.json").is_file() else {}
    finding = json.loads((bundle_dir / "finding.json").read_text()) if (bundle_dir / "finding.json").is_file() else {}
    fix_shas = [c.get("commit_sha", "") for c in ref.get("upstream_fix_commits") or []]
    current = ((finding.get("affected") or [{}])[0]).get("version", "")
    shape = classify_change(change.get("files") or [], fix_shas=fix_shas, current_version=current)

    result = {
        "schema_version": "1.0.0",
        "compared_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nixpkgs_pr": change.get("number"),
        "nixpkgs_merged_at": change.get("merged_at"),
        **shape,
    }
    if shape["shape"] == "patch-file":
        authored = _authored_inner_patch(bundle_dir)
        result["patch_files_in_pr"] = len(shape["patch_files"])
        best = None
        if authored is not None:
            # A nixpkgs PR can carry one patch per CVE. Score each file on its own
            # and keep the one that matches best; the union says nothing.
            for path in shape["patch_files"]:
                text = fetch_file(change["number"], path)
                if not text.strip():
                    continue
                s = _score_both_ways(authored, text)
                key = (s["exact"], s["payload_added_recall"], s["added_recall"])
                if best is None or key > best[0]:
                    best = (key, path, s)
        if best is None:
            result["scores"] = None
            result["note"] = "no authored inner patch to score, or every nixpkgs patch file was empty"
        else:
            result["matched_patch_file"] = best[1]
            result["scores"] = best[2]
    (bundle_dir / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def _comment_text(result: dict) -> str:
    shape = result["shape"]
    head = f"nixpkgs landed its own change for this CVE in NixOS/nixpkgs#{result['nixpkgs_pr']}"
    if result.get("nixpkgs_merged_at"):
        head += f", merged {result['nixpkgs_merged_at'][:10]}"
    head += "."
    if shape == "patch-file":
        s = result.get("scores") or {}
        if s:
            body = (f"It is an in-tree patch, the same shape as this PR. "
                    f"{s['payload_added_recall']:.0%} of this payload's added lines and "
                    f"{s['payload_removed_recall']:.0%} of its removed lines appear in the nixpkgs patch; "
                    f"in the other direction this payload covers {s['added_recall']:.0%} of theirs"
                    + (", an exact match." if s.get("exact") else "."))
            if result.get("patch_files_in_pr", 1) > 1:
                body += f" The nixpkgs PR carried {result['patch_files_in_pr']} patch files; the comparison is against {result['matched_patch_file'].rsplit('/', 1)[-1]}."
        else:
            body = "It is an in-tree patch, but there was nothing scorable to compare."
    elif shape == "same-fix-commit":
        body = f"It adopts the same upstream fix commit this PR backports ({result['commit_sha'][:12]}), so the two agree on the fix and differ only in packaging."
    elif shape == "upstream-bumped":
        body = (f"It is a version bump to {result['fixed_version']}. This PR patched {result.get('previous_version') or 'the packaged version'} in place "
                "instead; both remove the flaw, by different routes.")
    else:
        body = "Its shape was not one the comparison recognises; a person should read both."
    return head + " " + body + " Recorded in the bundle's comparison.json."


def watch(
    *,
    fork_prs: list[dict],
    bundles_root: Path,
    find_merged_nixpkgs_pr: Callable[[str], int | None],
    cve_in_tree: Callable[[str], bool],
    fetch_change: Callable[[int], dict | None],
    fetch_file: Callable[[int, str], str],
    comment: Callable[[int, str], None],
) -> dict[str, str]:
    """One pass over the fork's live-lane PRs. Returns {cve_id: waiting|landed|no-bundle}."""
    states: dict[str, str] = {}
    for pr in fork_prs:
        parsed = parse_fork_branch(pr.get("headRefName", ""))
        if not parsed:
            continue
        cve_id, _attr, bundle_id = parsed
        bundle_dir = _find_bundle(bundles_root, cve_id, bundle_id)
        if bundle_dir is None:
            states[cve_id] = "no-bundle"
            continue
        if (bundle_dir / "comparison.json").is_file():
            states[cve_id] = "landed"
            continue
        try:
            number = find_merged_nixpkgs_pr(cve_id)
            in_tree = number is None and cve_in_tree(cve_id)
        except RuntimeError:
            # A lookup that could not run says nothing; do not record it as waiting.
            states[cve_id] = "check-failed"
            continue
        if number is None and not in_tree:
            states[cve_id] = "waiting"
            continue
        try:
            change = fetch_change(number) if number is not None else None
            if change is None:
                states[cve_id] = "waiting"
                continue
            result = compare_bundle(bundle_dir, change, fetch_file=fetch_file)
        except RuntimeError:
            # Nothing is written on a failed fetch, so the next pass retries.
            states[cve_id] = "check-failed"
            continue
        comment(pr["number"], _comment_text(result))
        states[cve_id] = "landed"
    return states


def _find_bundle(root: Path, cve_id: str, bundle_id: str) -> Path | None:
    for d in sorted(root.glob(f"{cve_id}--*")):
        bj = d / "bundle.json"
        if bj.is_file():
            try:
                if json.loads(bj.read_text()).get("bundle_id") == bundle_id:
                    return d
            except json.JSONDecodeError:
                continue
    return None


def report(bundles_root: Path) -> dict:
    """Waiting versus landed across every bundle that has a live-lane shape."""
    waiting = 0
    landed: dict[str, int] = {}
    exact = 0
    for d in sorted(bundles_root.glob("CVE-*")):
        if d.name.startswith("CVE-0000-") or not (d / "patch.diff").is_file():
            continue
        ref = d / "upstream-ref.json"
        try:
            strategy = json.loads(ref.read_text()).get("eligibility", {}).get("patch_strategy") if ref.is_file() else None
        except json.JSONDecodeError:
            strategy = None
        if strategy != "source-backport":
            continue
        c = d / "comparison.json"
        if not c.is_file():
            waiting += 1
            continue
        data = json.loads(c.read_text())
        landed[data.get("shape", "other")] = landed.get(data.get("shape", "other"), 0) + 1
        if (data.get("scores") or {}).get("exact"):
            exact += 1
    return {"waiting": waiting, "landed": landed, "exact_matches": exact}


# ─── the real network functions ────────────────────────────────────────────────


def _gh_json(args: list[str]):
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:300])
    return json.loads(proc.stdout or "null")


def gh_find_merged_nixpkgs_pr(cve_id: str) -> int | None:
    data = _gh_json(["search", "prs", "--repo", "NixOS/nixpkgs", cve_id, "--merged",
                     "--json", "number,closedAt", "--limit", "5"])
    if not data:
        return None
    data.sort(key=lambda d: d.get("closedAt") or "")
    return int(data[0]["number"])


def gh_cve_in_tree(cve_id: str) -> bool:
    count = _gh_json(["api", "-X", "GET", "search/code", "-f", f"q={cve_id} repo:NixOS/nixpkgs",
                      "--jq", ".total_count"])
    return bool(count)


def gh_fetch_change(number: int) -> dict | None:
    pr = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}"])
    files = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}/files", "--paginate"])
    return {"number": number, "merged_at": pr.get("merged_at"), "files": files or []}


def gh_fetch_file(number: int, path: str) -> str:
    pr = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}"])
    sha = (pr.get("merge_commit_sha") or pr.get("head", {}).get("sha") or "")
    proc = subprocess.run(["gh", "api", f"repos/NixOS/nixpkgs/contents/{path}?ref={sha}",
                           "-H", "Accept: application/vnd.github.raw"], capture_output=True, text=True, timeout=120)
    if proc.returncode == 0:
        return proc.stdout
    if "404" in proc.stderr or "Not Found" in proc.stderr:
        return ""  # genuinely absent at that commit; nothing to score
    raise RuntimeError(f"fetching {path}: {proc.stderr.strip()[:200]}")


def gh_comment(fork_repo: str) -> Callable[[int, str], None]:
    def _post(number: int, body: str) -> None:
        subprocess.run(["gh", "pr", "comment", str(number), "--repo", fork_repo, "--body", body],
                       check=True, capture_output=True, text=True, timeout=120)
    return _post


def add_parser(subs: argparse._SubParsersAction) -> None:
    w = subs.add_parser("watch", help="compare live-lane fork PRs against what nixpkgs landed")
    w.add_argument("--fork", default="Ad-Astra-Computing/nixpkgs")
    w.add_argument("--bundles-root", type=Path, default=Path("traces/example"))
    w.add_argument("--dry-run", action="store_true", help="compare and record, but post no comment")
    r = subs.add_parser("report", help="waiting versus landed across live-lane bundles")
    r.add_argument("--bundles-root", type=Path, default=Path("traces/example"))


def run(args: argparse.Namespace) -> int:
    if args.compare_cmd == "report":
        print(json.dumps(report(args.bundles_root), indent=2))
        return 0
    prs = _gh_json(["pr", "list", "--repo", args.fork, "--state", "open", "--limit", "200",
                    "--json", "number,headRefName"])
    poster = (lambda n, b: print(f"[dry-run] would comment on #{n}: {b}")) if args.dry_run else gh_comment(args.fork)
    states = watch(fork_prs=prs or [], bundles_root=args.bundles_root,
                   find_merged_nixpkgs_pr=gh_find_merged_nixpkgs_pr, cve_in_tree=gh_cve_in_tree,
                   fetch_change=gh_fetch_change, fetch_file=gh_fetch_file, comment=poster)
    for cve, state in sorted(states.items()):
        print(f"{cve}: {state}")
    return 0
