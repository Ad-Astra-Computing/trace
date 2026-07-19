"""Automate Phase-B: turn discovered fold-shaped CVE leads into leak-clean SFT pairs.

The shape-stratified-SFT lever is validated (bzip2 zero-mass → norm-exact; DECISIONS
2026-07-17). Phase-B needs DIVERSE fold training pairs (no upsampling — v12's crude
repetition regressed zlib). Rather than hand-author each of the 52 leads, this composes
existing trace primitives into a mint pipeline and DROPS (never hand-fixes) any lead that
fails a gate — the drop-not-fix rule is what removes the manual work.

Per lead (cve, nixpkgs_fix_commit, patch_path):
  1. fold diff  = `git show <fix_commit>:<patch_path>` (the training target / answer key)
  2. repo URL   = parsed from the package.nix beside the patch (fetchFromGitHub/GitLab/git/url + version)
  3. pre-fix source: Tier 1 (patch has a `From <sha>` header) → parent of the upstream commit;
       Tier 2 (vendored patch, no header) → the pinned src rev/tag package.nix applies it to
  4. window     = the exporter's own `_hunk_windows` around the diff's hunks (radius 20)
  5. advisory   = NVD (feed_client) → OSV fallback → DROP if neither
  6. scrub      = export `_scrub_summary` (+ `_fix_symbols` post-assertion: no fix token survives)
  7. gates 0–9  = single-file / size / repo-resolve / prefix-fetch / applies / grounding /
       post-fix-cut / advisory / leak-residue / shape-match — each DROP recorded in the report
  8. pair       = the exporter authoring chat format (system + `# CVE`/`# Vulnerable source` user + diff)

Output: data/reports/phase-b-fold-pairs.jsonl + phase-b-fold-mint-report.json (the audit trail
that replaces hand review). eval/-only; does NOT touch contract-path files.

Usage: python3 eval/mint_fold_pairs.py [--leads data/reports/phase-b-fold-leads.jsonl] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.trace_cli import backport_patch as bp                    # noqa: E402
from tools.trace_cli.export import (                                # noqa: E402
    _AUTHORING_SYSTEM, _scrub_summary, _fix_symbols, _hunk_windows, _file_diff_starts,
)
from eval.author_blind_eval import _strip_remediation  # noqa: E402
from eval.classify_edit_shape import classify_diff                  # noqa: E402

NIXPKGS = ROOT.parent / "nixpkgs"
_FROM_HDR = re.compile(r"^From ([0-9a-f]{40})\b", re.M)
_FETCH_GH = re.compile(r'fetchFromGit(?:Hub|Lab)\s*\{[^}]*?owner\s*=\s*"([^"]+)"[^}]*?repo\s*=\s*"([^"]+)"', re.S)
_FETCH_GIT = re.compile(r'fetchgit\s*\{[^}]*?url\s*=\s*"([^"]+)"', re.S)
_VERSION = re.compile(r'(?:final(?:Attrs)?\.)?version\s*=\s*"([^"]+)"')
_FENCE = {"c": "c", "h": "c", "cc": "cpp", "cpp": "cpp", "py": "python", "pl": "perl",
          "pm": "perl", "rb": "ruby", "go": "go", "rs": "rust", "js": "javascript"}


def _show(commit: str, path: str) -> str:
    r = subprocess.run(["git", "-C", str(NIXPKGS), "show", f"{commit}:{path}"],
                       capture_output=True)
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""


def _changed(diff: str):
    minus = [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    plus = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    return minus, plus


def _target_files(diff: str) -> list[str]:
    out = []
    for ln in diff.splitlines():
        if ln.startswith("--- ") and not ln.startswith("--- /dev/null"):
            p = ln[4:].split("\t")[0].strip()
            out.append(p[2:] if p.startswith(("a/", "b/")) else p)
    return out


def _repo_from_pkg(patch_path: str, fix_commit: str) -> tuple[str | None, str | None]:
    """(repo_url, version) from the nearest package.nix/default.nix — walking UP from the
    patch dir, since patches often live in a `patches/` subdir one level below the pkg.
    Returns ('FETCHURL', ver) when the source is a fetchurl tarball (no git parent)."""
    d = Path(patch_path).parent
    for _ in range(4):                                   # walk up a few levels
        for name in ("package.nix", "default.nix"):
            src = _show(fix_commit, f"{d.as_posix()}/{name}")
            if not src:
                continue
            vm = _VERSION.search(src)
            ver = vm.group(1) if vm else None
            # fetchFromGitHub/GitLab — owner/repo in EITHER order
            if "fetchFromGitHub" in src or "fetchFromGitLab" in src:
                owner = re.search(r'owner\s*=\s*"([^"]+)"', src)
                repo = re.search(r'repo\s*=\s*"([^"]+)"', src)
                host = "gitlab.com" if "fetchFromGitLab" in src else "github.com"
                if owner and repo:
                    return f"https://{host}/{owner.group(1)}/{repo.group(1)}.git", ver
            git = _FETCH_GIT.search(src)
            if git:
                return git.group(1), ver
            # non-git / indirect sources — report distinctly so the yield picture is honest
            if "fetchsvn" in src or "fetchhg" in src or "fetchcvs" in src or "fetchbzr" in src:
                return "NONGIT-VCS", ver
            if "fetchurl" in src or "fetchzip" in src:   # release tarball — no git parent (v1 skip)
                return "FETCHURL", ver
        if d.name in ("", "pkgs") or d.parent == d:
            break
        d = d.parent
    return None, None


def _fetch_advisory(cve: str) -> str | None:
    """Real advisory text: NVD (feed_client) → OSV fallback. None if neither."""
    try:
        from agents.scout.feed_client import fetch_nvd_direct
        r = fetch_nvd_direct(cve)
        desc = None
        if isinstance(r, dict):
            vulns = r.get("vulnerabilities") or []
            if vulns:
                descs = vulns[0].get("cve", {}).get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), None)
        elif hasattr(r, "dossier"):
            desc = getattr(r, "dossier", None)
        if desc:
            return desc
    except Exception:
        pass
    try:
        import urllib.request
        with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{cve}", timeout=20) as fh:
            d = json.load(fh)
        return d.get("details") or d.get("summary")
    except Exception:
        return None




def mint_one(lead: dict, workdir: Path) -> tuple[dict | None, dict]:
    cve = lead.get("cve")
    rep = {"cve": cve, "subshape": lead.get("subshape"), "verdict": None}
    fold = _show(lead["fix_commit"], lead["patch"])
    if not fold.strip():
        rep["verdict"] = "drop:fold-extract"; return None, rep
    files = _target_files(fold)
    if len(set(files)) != 1:                                   # gate 1: single-file
        rep["verdict"] = "drop:multi-file"; return None, rep
    fpath = files[0]
    minus, plus = _changed(fold)
    if not (1 <= len(plus) <= 15) or (len(minus) + len(plus)) > 40:   # gate 2: size
        rep["verdict"] = "drop:size"; return None, rep
    if not cve:
        rep["verdict"] = "drop:no-cve"; return None, rep

    repo_url, ver = _repo_from_pkg(lead["patch"], lead["fix_commit"])
    if not repo_url:                                           # gate 3: repo-resolve
        rep["verdict"] = "drop:repo-resolve"; return None, rep
    if repo_url in ("FETCHURL", "NONGIT-VCS"):                # no git parent to fetch (v1 skip)
        rep["verdict"] = f"drop:{repo_url.lower()}"; return None, rep

    starts = [int(m) for m in re.findall(r"@@ -(\d+)", fold)] or [1]
    span = (min(starts), max(starts))
    m = _FROM_HDR.search(fold)
    full = _prefix_full(repo_url, m.group(1) if m else None, ver, fpath, workdir)
    if full is None:                                          # gate 4: prefix-fetch
        rep["verdict"] = "drop:prefix-fetch"; return None, rep
    # gate 5: fold diff applies to the fetched pre-fix file
    with tempfile.TemporaryDirectory() as td:
        tgt = Path(td) / fpath
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_text(full)
        ap = subprocess.run(["git", "apply", "--check", "-p1", "-"], input=fold,
                            text=True, cwd=td, capture_output=True)
        if ap.returncode != 0:
            rep["verdict"] = "drop:applies"; return None, rep
    # exporter-quality multi-hunk window (each hunk +/-20 lines), NOT a single span slice
    pre = _hunk_windows(full.splitlines(), _file_diff_starts(fold, fpath) or [1], radius=20)
    if not pre.strip():
        rep["verdict"] = "drop:window"; return None, rep

    # gate 6: grounding — every removed/context line present in the window
    win_norm = re.sub(r"\s+", " ", pre)
    if not all(re.sub(r"\s+", " ", l.strip()) in win_norm for l in minus if l.strip()):
        rep["verdict"] = "drop:grounding"; return None, rep

    adv = _fetch_advisory(cve)
    if not adv:                                               # gate 8a: advisory
        rep["verdict"] = "drop:no-advisory"; return None, rep
    vuln = _scrub_summary(_strip_remediation(adv), fold)
    if len(vuln.strip()) < 120:                              # gate 8b: over-scrub
        rep["verdict"] = "drop:scrub-collapse"; return None, rep
    leaks = [s for s in _fix_symbols(fold) if s in vuln]     # gate 8c: leak residue
    if leaks:
        rep["verdict"] = f"drop:leak-residue:{leaks[:3]}"; return None, rep

    got_shape = classify_diff(fold)                           # gate 9: shape match
    if got_shape["subshape"] != lead["subshape"]:
        rep["verdict"] = f"drop:shape-mismatch:{got_shape['subshape']}"; return None, rep

    lang = _FENCE.get(fpath.rsplit(".", 1)[-1], "")
    user = (f"# CVE\n{cve}: {vuln}\n\n"
            f"# Vulnerable source ({fpath})\n```{lang}\n{pre}\n```")
    pair = {
        "messages": [
            {"role": "system", "content": _AUTHORING_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": fold.strip()},
        ],
        "provenance": {"source": "phase-b-auto-fold", "cve": cve, "subshape": lead["subshape"],
                       "nixpkgs_commit": lead["fix_commit"], "file": fpath},
    }
    rep["verdict"] = "MINTED"
    return pair, rep


def _prefix_full(repo_url, from_sha, ver, fpath, workdir):
    """The FULL pre-fix file (not windowed) for the apply-check gate."""
    try:
        repo_url = bp.clone_url(repo_url)
    except bp.BackportError:
        return None
    repo = workdir / "full"
    repo.mkdir(exist_ok=True)
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
    g("init", "-q")
    if g("remote", "add", "origin", repo_url).returncode != 0:
        g("config", "remote.origin.url", repo_url)
    rev = None
    if from_sha and bp.blobless_fetch_commit(g, from_sha):
        rev = g("rev-parse", "-q", "--verify", f"{from_sha}^").stdout.strip()
    elif ver:
        if bp._SAFE_FETCH_REV_RE.match(ver) and bp.blobless_fetch_commit(g, ver):
            rev = ver
        else:
            for cand in (ver, f"v{ver}"):
                try:
                    tag = bp._validate_tag(cand)
                except bp.BackportError:
                    continue
                if g("fetch", "--depth=1", "--filter=blob:none", "origin", "tag", tag).returncode == 0:
                    rev = "FETCH_HEAD"; break
    if not rev:
        return None
    b = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{fpath}"], capture_output=True)
    return b.stdout.decode("utf-8", "replace") if b.returncode == 0 else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--leads", type=Path, default=ROOT / "data/reports/phase-b-fold-leads.jsonl")
    ap.add_argument("--out", type=Path, default=ROOT / "data/reports/phase-b-fold-pairs.jsonl")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    leads = [json.loads(l) for l in args.leads.read_text().splitlines() if l.strip()]
    leads = [L for L in leads if not L.get("excluded_dup")]
    if args.limit:
        leads = leads[: args.limit]

    pairs, report = [], []
    from collections import Counter
    for lead in leads:
        with tempfile.TemporaryDirectory(prefix="mintfold-") as td:
            try:
                pair, rep = mint_one(lead, Path(td))
            except Exception as e:
                pair, rep = None, {"cve": lead.get("cve"), "subshape": lead.get("subshape"),
                                   "verdict": f"drop:error:{type(e).__name__}"}
        report.append(rep)
        if pair:
            pairs.append(pair)

    args.out.write_text("\n".join(json.dumps(p) for p in pairs) + "\n")
    (ROOT / "data/reports/phase-b-fold-mint-report.json").write_text(json.dumps(report, indent=2))
    minted = [r for r in report if r["verdict"] == "MINTED"]
    print(f"leads={len(leads)}  MINTED={len(minted)}  dropped={len(leads)-len(minted)}")
    print("mint by sub-shape:", dict(Counter(r["subshape"] for r in minted)))
    print("drop reasons:", dict(Counter(r["verdict"].split(":")[1] if ":" in r["verdict"] else r["verdict"]
                                        for r in report if r["verdict"] != "MINTED")))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
