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
import time
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


def _norm_name(s: str) -> str:
    """A package name reduced to what survives nixpkgs's naming: no case, no
    punctuation, no trailing version digits, so `grub2` meets `grub`."""
    return re.sub(r"[^a-z0-9]", "", s.lower().removesuffix(".nix")).rstrip("0123456789")


def package_name_tokens(bundle_dir: Path) -> set[str]:
    """Normalised names for the bundle's package, from its nixpkgs paths and attr."""
    raw = {Path(f).parent.name for f in package_files(bundle_dir)}
    ri = bundle_dir / "resolver-input.json"
    if ri.is_file():
        try:
            attr = json.loads(ri.read_text()).get("attr_path") or ""
        except json.JSONDecodeError:
            attr = ""
        if attr:
            raw.add(attr.replace(".", ""))
    return {t for t in (_norm_name(r) for r in raw) if len(t) >= 3}


def change_touches_package(change: dict, bundle_dir: Path) -> bool | None:
    """Whether a merged nixpkgs change touches this bundle's package at all.

    The PR search matches a CVE id anywhere in a pull request, a comment on an
    unrelated change included, so a hit is not yet a landing. The test is on
    names rather than on whole paths: a package moves between the by-name layout
    and a category directory, and a bundle's recorded paths are those of its own
    pinned revision, so path equality misses landings that are real. Returns
    None when the bundle names no package and the question cannot be asked.
    """
    tokens = package_name_tokens(bundle_dir)
    if not tokens:
        return None
    for f in change.get("files") or []:
        for seg in (f.get("filename") or "").split("/"):
            seg = _norm_name(seg)
            if len(seg) < 3:
                continue
            for tok in tokens:
                if seg == tok or (min(len(seg), len(tok)) >= 4
                                  and (seg.startswith(tok) or tok.startswith(seg))):
                    return True
    return False


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
    find_landed_in_tree: Callable[[str, Path], int | None],
    fetch_change: Callable[[int], dict | None],
    fetch_file: Callable[[int, str], str],
    comment: Callable[[int, str], None],
    post: bool = False,
) -> dict[str, str]:
    """One pass over every live-lane bundle. Returns {bundle dir: waiting|landed|check-failed}.

    A fork PR branch whose bundle is missing is the one entry keyed by CVE id,
    under `no-bundle`; it has no directory to name.

    A bundle earns its comparison by existing, not by having a fork PR. Most
    live-lane bundles have no PR: opening one is public and needs the operator's
    approval, while the grading this function does is local and needs none. A
    fork PR, when there is one, only decides where a comment could go.

    A comparison is always recorded. The fork PR comment is public, and the
    standard forbids public posting without the operator's explicit approval, so
    the comment is written beside the bundle as a draft and posted only when the
    operator passed `post=True` for this run.
    """
    states: dict[str, str] = {}
    pr_for_bundle: dict[Path, dict] = {}
    for pr in fork_prs:
        parsed = parse_fork_branch(pr.get("headRefName", ""))
        if not parsed:
            continue
        cve_id, _attr, bundle_id = parsed
        bundle_dir = _find_bundle(bundles_root, cve_id, bundle_id)
        if bundle_dir is None:
            states[cve_id] = "no-bundle"
            continue
        pr_for_bundle.setdefault(bundle_dir, pr)

    # Keyed by directory rather than CVE id: several CVEs have two bundles, and a
    # sibling's verdict must not overwrite the one before it or the exit code lies.
    landed_pr: dict[str, int | None] = {}
    for bundle_dir in dict.fromkeys([*pr_for_bundle, *live_lane_bundles(bundles_root)]):
        pr = pr_for_bundle.get(bundle_dir)
        cve_id = bundle_dir.name.split("--")[0]
        key = bundle_dir.name
        if (bundle_dir / "comparison.json").is_file():
            states[key] = "landed"
            continue
        try:
            # One search per CVE, not per bundle: the search API's budget is small
            # and two bundles for one CVE ask the same question.
            if cve_id in landed_pr:
                number = landed_pr[cve_id]
            else:
                number = find_merged_nixpkgs_pr(cve_id)
                landed_pr[cve_id] = number
        except RuntimeError as e:
            # A lookup that could not run says nothing; do not record it as waiting.
            print(f"{cve_id}: check-failed: PR search: {e}")
            states[key] = "check-failed"
            continue
        if number is None:
            try:
                number = find_landed_in_tree(cve_id, bundle_dir)
            except RuntimeError as e:
                # The tree check is advisory: the PR search ran and found nothing,
                # which is a real answer on its own.
                print(f"{cve_id}: tree check skipped: {e}")
        if number is None:
            states[key] = "waiting"
            continue
        try:
            change = fetch_change(number)
            if change is None:
                states[key] = "waiting"
                continue
            if change_touches_package(change, bundle_dir) is False:
                # The search matched the CVE id in a pull request that changes
                # some other package. That is not a landing.
                print(f"{cve_id}: nixpkgs PR {number} touches no file of this package")
                states[key] = "waiting"
                continue
            result = compare_bundle(bundle_dir, change, fetch_file=fetch_file)
        except RuntimeError as e:
            # Nothing is written on a failed fetch, so the next pass retries.
            print(f"{cve_id}: check-failed: fetch: {e}")
            states[key] = "check-failed"
            continue
        if pr is not None:
            text = f"Draft comment for fork PR #{pr['number']}. Post only with the operator's explicit approval.\n\n" + _comment_text(result) + "\n"
            (bundle_dir / "comparison-comment.md").write_text(text)
            if post:
                comment(pr["number"], _comment_text(result))
        states[key] = "landed"
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


def live_lane_bundles(bundles_root: Path) -> list[Path]:
    """Every bundle whose payload is a source backport, in CVE order."""
    out: list[Path] = []
    for d in sorted(bundles_root.glob("CVE-*")):
        if d.name.startswith("CVE-0000-") or not (d / "patch.diff").is_file():
            continue
        ref = d / "upstream-ref.json"
        try:
            strategy = json.loads(ref.read_text()).get("eligibility", {}).get("patch_strategy") if ref.is_file() else None
        except json.JSONDecodeError:
            strategy = None
        if strategy == "source-backport":
            out.append(d)
    return out


def report(bundles_root: Path) -> dict:
    """Waiting versus landed across every bundle that has a live-lane shape."""
    waiting = 0
    landed: dict[str, int] = {}
    exact = 0
    for d in live_lane_bundles(bundles_root):
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


_SEARCH_INTERVAL = 2.2  # seconds; GitHub's search API allows 30 authenticated requests a minute
_last_search = 0.0


def _search_throttle(now: Callable[[], float] = time.monotonic, pause: Callable[[float], None] = time.sleep) -> None:
    """Space out search requests. A corpus pass asks once per CVE, which is more
    than the search API's per-minute budget if the requests go out back to back."""
    global _last_search
    wait = _SEARCH_INTERVAL - (now() - _last_search)
    if wait > 0:
        pause(wait)
    _last_search = now()


def gh_find_merged_nixpkgs_pr(cve_id: str) -> int | None:
    _search_throttle()
    data = _gh_json(["search", "prs", "--repo", "NixOS/nixpkgs", cve_id, "--merged",
                     "--json", "number,closedAt", "--limit", "5"])
    if not data:
        return None
    data.sort(key=lambda d: d.get("closedAt") or "")
    return int(data[0]["number"])


def _gh_api_json(path: str):
    return _gh_json(["api", path])


def _gh_raw(path: str) -> str:
    """Raw file contents at a contents-API path; empty when absent."""
    proc = subprocess.run(["gh", "api", path, "-H", "Accept: application/vnd.github.raw"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode == 0:
        return proc.stdout
    if "404" in proc.stderr or "Not Found" in proc.stderr:
        return ""
    raise RuntimeError(f"fetching {path}: {proc.stderr.strip()[:200]}")


_TREE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")


def _tree_path_ok(path: str) -> bool:
    """A repository-relative path safe to splice into a contents-API URL: plain
    segments, no `..`, no query or fragment characters."""
    return bool(_TREE_PATH_RE.match(path)) and ".." not in path.split("/")


def package_files(bundle_dir: Path) -> list[str]:
    """nixpkgs paths the bundle's patch touches: the cert's record first, then the
    by-name layout of the resolver's attr when no cert has run."""
    build = bundle_dir / "build.json"
    if build.is_file():
        files = ((json.loads(build.read_text()).get("patch_apply") or {}).get("files_changed")) or []
        if files:
            return [str(f) for f in files if _tree_path_ok(str(f))]
    ri = bundle_dir / "resolver-input.json"
    attr = (json.loads(ri.read_text()).get("attr_path") or "") if ri.is_file() else ""
    if attr and "." not in attr and _tree_path_ok(attr):
        return [f"pkgs/by-name/{attr[:2]}/{attr}/package.nix"]
    return []


def find_landed_in_tree(
    cve_id: str,
    bundle_dir: Path,
    *,
    gh_json: Callable[[str], object] = _gh_api_json,
    gh_raw: Callable[[str], str] = _gh_raw,
) -> int | None:
    """Has the CVE reached the package's own files on master, and under which PR?

    Contents API only, so it runs under the default Actions token. It lists the
    package directory for a file named after the CVE, reads the `.nix` files the
    bundle touched for the id, and on a hit walks the directory's recent commits
    for one whose message names the CVE, returning that commit's merged PR.
    """
    files = package_files(bundle_dir)
    dirs: list[str] = []
    for f in files:
        d = f.rsplit("/", 1)[0] if "/" in f else ""
        if d and d not in dirs:
            dirs.append(d)
    for d in dirs:
        try:
            listing = gh_json(f"repos/NixOS/nixpkgs/contents/{d}?ref=master") or []
        except RuntimeError as e:
            if "404" in str(e) or "Not Found" in str(e):
                # The package moved or was renamed since the cert; nothing to read here.
                continue
            raise
        names = [e.get("name", "") for e in listing if isinstance(e, dict)]
        hit = any(cve_id in n for n in names)
        if not hit:
            for f in files:
                if f.startswith(d + "/") and f.endswith(".nix") and f.rsplit("/", 1)[1] in names:
                    if cve_id in gh_raw(f"repos/NixOS/nixpkgs/contents/{f}?ref=master"):
                        hit = True
                        break
        if not hit:
            continue
        commits = gh_json(f"repos/NixOS/nixpkgs/commits?path={d}&sha=master&per_page=30") or []
        for c in commits:
            if not isinstance(c, dict) or cve_id not in ((c.get("commit") or {}).get("message") or ""):
                continue
            sha = str(c.get("sha") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                continue
            pulls = gh_json(f"repos/NixOS/nixpkgs/commits/{sha}/pulls") or []
            merged = [p for p in pulls if isinstance(p, dict) and p.get("merged_at")]
            if merged:
                return int(merged[0]["number"])
        print(f"{cve_id}: in tree under {d} but no commit names it; waiting for the next pass")
    return None


def gh_fetch_change(number: int) -> dict | None:
    pr = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}"])
    files = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}/files", "--paginate"])
    return {"number": number, "merged_at": pr.get("merged_at"), "files": files or []}


def gh_fetch_file(number: int, path: str) -> str:
    pr = _gh_json(["api", f"repos/NixOS/nixpkgs/pulls/{number}"])
    sha = (pr.get("merge_commit_sha") or pr.get("head", {}).get("sha") or "")
    return _gh_raw(f"repos/NixOS/nixpkgs/contents/{path}?ref={sha}")  # empty when absent at that commit


def gh_comment(fork_repo: str) -> Callable[[int, str], None]:
    def _post(number: int, body: str) -> None:
        subprocess.run(["gh", "pr", "comment", str(number), "--repo", fork_repo, "--body", body],
                       check=True, capture_output=True, text=True, timeout=120)
    return _post


def add_parser(subs: argparse._SubParsersAction) -> None:
    w = subs.add_parser("watch", help="compare live-lane bundles against what nixpkgs landed")
    w.add_argument("--fork", default="Ad-Astra-Computing/nixpkgs")
    w.add_argument("--bundles-root", type=Path, default=Path("traces/example"))
    w.add_argument("--dry-run", action="store_true", help="compare and record, but post no comment")
    w.add_argument("--post", action="store_true",
                   help="post the drafted comment on the fork PR. Public posting needs the operator's "
                        "explicit approval for this run; without --post the draft stays beside the bundle")
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
                   find_merged_nixpkgs_pr=gh_find_merged_nixpkgs_pr, find_landed_in_tree=find_landed_in_tree,
                   fetch_change=gh_fetch_change, fetch_file=gh_fetch_file, comment=poster,
                   post=bool(args.post and not args.dry_run))
    for cve, state in sorted(states.items()):
        print(f"{cve}: {state}")
    if any(v == "check-failed" for v in states.values()):
        return 3
    return 0
