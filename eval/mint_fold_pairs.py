"""Automate Phase-B: turn discovered fold-shaped CVE leads into leak-clean SFT pairs.

The shape-stratified-SFT lever is validated (bzip2 zero-mass → norm-exact; DECISIONS
2026-07-17). Phase-B needs DIVERSE fold training pairs (no upsampling — v12's crude
repetition regressed zlib). Rather than hand-author each lead, this mints them.

KEY: the pre-fix source window is RECONSTRUCTED from the fold diff itself (context +
removed lines, dropping added lines), NOT fetched. A fetch-based v1 yielded ~1/52 because
nixpkgs security sources are dominated by multi-file fixes + mirror://-tarball / non-git
sources with no windowable git parent (DECISIONS 2026-07-19). Reconstruction sidesteps
both: multi-file is natural (a window per file), and no upstream fetch is needed. The
window is the ±(patch-context) neighborhood of each change — thinner than the ±20 source
window of the bundle-derived corpus, but it shows the vulnerable region, which is what
teaching the fold SHAPE requires. The prompt still carries the real (leak-scrubbed) CVE
advisory; the completion is the upstream fold diff.

Gates (DROP, never hand-fix): size / window-nontrivial / advisory / leak-residue /
shape-match. Output: data/reports/phase-b-fold-pairs.jsonl + phase-b-fold-mint-report.json.
eval/-only; no contract-path change; no API/HF spend (NVD/OSV advisory fetch only).

Usage: python3 eval/mint_fold_pairs.py [--leads ...] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.trace_cli.export import _AUTHORING_SYSTEM, _scrub_summary, _fix_symbols  # noqa: E402
from eval.author_blind_eval import _strip_remediation  # noqa: E402
from eval.classify_edit_shape import classify_diff  # noqa: E402

NIXPKGS = ROOT.parent / "nixpkgs"
_FENCE = {
    "c": "c",
    "h": "c",
    "cc": "cpp",
    "cpp": "cpp",
    "hpp": "cpp",
    "py": "python",
    "pl": "perl",
    "pm": "perl",
    "rb": "ruby",
    "go": "go",
    "rs": "rust",
    "js": "javascript",
}


def _show(commit: str, path: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(NIXPKGS), "show", f"{commit}:{path}"], capture_output=True
    )
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""


def _changed(diff: str):
    minus = [
        l[1:]
        for l in diff.splitlines()
        if l.startswith("-") and not l.startswith("---")
    ]
    plus = [
        l[1:]
        for l in diff.splitlines()
        if l.startswith("+") and not l.startswith("+++")
    ]
    return minus, plus


def _norm_path(p: str) -> str:
    p = p.split("\t")[0].strip()
    return p[2:] if p.startswith(("a/", "b/")) else p


def _target_files(diff: str) -> list[str]:
    out = []
    for ln in diff.splitlines():
        if ln.startswith("+++ ") and not ln.startswith("+++ /dev/null"):
            out.append(_norm_path(ln[4:]))
    return out


def _prefix_from_diff(fold: str) -> tuple[str | None, list[str]]:
    """Reconstruct the pre-fix window per file from the diff's hunks (context + removed
    lines; added lines dropped). Returns (window_text, files). No upstream fetch."""
    files: dict[str, list[str]] = {}
    cur = None
    for ln in fold.splitlines():
        if ln.startswith("+++ "):
            cur = _norm_path(ln[4:])
            if cur != "/dev/null":
                files.setdefault(cur, [])
            continue
        if ln.startswith("@@"):
            if cur in files and files[cur]:
                files[cur].append("    ...")  # hunk separator
            continue
        if ln.startswith(
            (
                "--- ",
                "diff ",
                "index ",
                "new file",
                "deleted file",
                "similarity",
                "rename",
                "old mode",
                "new mode",
                "Binary",
            )
        ):
            continue
        if cur is None or cur not in files:
            continue
        if ln.startswith("+"):
            continue  # added = post-fix, dropped
        if ln.startswith("-"):
            files[cur].append(ln[1:])  # removed = pre-fix
        elif ln.startswith(" "):
            files[cur].append(ln[1:])  # context = pre-fix
    blocks, kept = [], []
    for path, lines in files.items():
        body = "\n".join(lines).strip()
        if body and body != "...":
            blocks.append(f"# {path}\n{body}")
            kept.append(path)
    return ("\n\n".join(blocks) if blocks else None), kept


def _jitter(window: str, seed: str) -> str:
    """Edge-trim jitter (Fable): remove 0-3 lines from ONE deterministically-chosen edge so
    the fold's position in the thin reconstructed window varies instead of being dead-center
    — converts 'position perfectly predicts the fix' into a noisy predictor, keeping the
    SHAPE signal load-bearing. Deterministic by CVE (reproducible), no fetch."""
    import hashlib

    lines = window.split("\n")
    if len(lines) < 10:
        return window
    h = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
    trim = (h >> 1) % 4  # 0-3 lines
    if trim == 0:
        return window
    return "\n".join(lines[trim:] if (h & 1) == 0 else lines[:-trim])


def _fetch_advisory(cve: str) -> str | None:
    """Real advisory text: NVD (feed_client) → OSV fallback. None if neither."""
    try:
        from agents.scout.feed_client import fetch_nvd_direct

        r = fetch_nvd_direct(cve)
        if isinstance(r, dict):
            vulns = r.get("vulnerabilities") or []
            if vulns:
                descs = vulns[0].get("cve", {}).get("descriptions", [])
                d = next((x["value"] for x in descs if x.get("lang") == "en"), None)
                if d:
                    return d
        elif getattr(r, "dossier", None):
            return r.dossier
    except Exception:
        pass
    try:
        import urllib.request

        with urllib.request.urlopen(
            f"https://api.osv.dev/v1/vulns/{cve}", timeout=20
        ) as fh:
            d = json.load(fh)
        return d.get("details") or d.get("summary")
    except Exception:
        return None


def mint_one(lead: dict) -> tuple[dict | None, dict]:
    cve = lead.get("cve")
    rep = {"cve": cve, "subshape": lead.get("subshape"), "verdict": None}
    fold = _show(lead["fix_commit"], lead["patch"])
    if not fold.strip():
        rep["verdict"] = "drop:fold-extract"
        return None, rep
    if not _target_files(fold):
        rep["verdict"] = "drop:no-target"
        return None, rep
    minus, plus = _changed(fold)
    if (
        not (1 <= len(plus) <= 20) or (len(minus) + len(plus)) > 60
    ):  # size (multi-file aware)
        rep["verdict"] = "drop:size"
        return None, rep
    if not cve:
        rep["verdict"] = "drop:no-cve"
        return None, rep

    pre, files = _prefix_from_diff(fold)  # reconstruct pre-fix window
    if not pre or len(pre.strip()) < 40:
        rep["verdict"] = "drop:window"
        return None, rep
    pre = _jitter(pre, cve)  # break the centered-position prior

    adv = _fetch_advisory(cve)
    if not adv:
        rep["verdict"] = "drop:no-advisory"
        return None, rep
    vuln = _scrub_summary(_strip_remediation(adv), fold)
    if len(vuln.strip()) < 120:  # over-scrub
        rep["verdict"] = "drop:scrub-collapse"
        return None, rep
    leaks = [s for s in _fix_symbols(fold) if s in vuln]
    if leaks:
        rep["verdict"] = f"drop:leak-residue:{leaks[:3]}"
        return None, rep

    got = classify_diff(fold)  # extraction sanity
    if got["subshape"] != lead["subshape"]:
        rep["verdict"] = f"drop:shape-mismatch:{got['subshape']}"
        return None, rep

    ext = files[0].rsplit(".", 1)[-1] if "." in files[0] else ""
    lang = _FENCE.get(ext, "")
    hdr = ", ".join(files)
    user = f"# CVE\n{cve}: {vuln}\n\n# Vulnerable source ({hdr})\n```{lang}\n{pre}\n```"
    pair = {
        "messages": [
            {"role": "system", "content": _AUTHORING_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": fold.strip()},
        ],
        "provenance": {
            "source": "phase-b-auto-fold",
            "cve": cve,
            "subshape": lead["subshape"],
            "nixpkgs_commit": lead["fix_commit"],
            "files": files,
            "window": "diff-reconstructed",
        },
    }
    rep["verdict"] = "MINTED"
    return pair, rep


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--leads", type=Path, default=ROOT / "data/reports/phase-b-fold-leads.jsonl"
    )
    ap.add_argument(
        "--out", type=Path, default=ROOT / "data/reports/phase-b-fold-pairs.jsonl"
    )
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    leads = [json.loads(l) for l in args.leads.read_text().splitlines() if l.strip()]
    leads = [L for L in leads if not L.get("excluded_dup")]
    if args.limit:
        leads = leads[: args.limit]

    pairs, report = [], []
    for lead in leads:
        try:
            pair, rep = mint_one(lead)
        except Exception as e:
            pair, rep = (
                None,
                {
                    "cve": lead.get("cve"),
                    "subshape": lead.get("subshape"),
                    "verdict": f"drop:error:{type(e).__name__}",
                },
            )
        report.append(rep)
        if pair:
            pairs.append(pair)

    args.out.write_text("\n".join(json.dumps(p) for p in pairs) + "\n")
    (ROOT / "data/reports/phase-b-fold-mint-report.json").write_text(
        json.dumps(report, indent=2)
    )
    minted = [r for r in report if r["verdict"] == "MINTED"]
    print(
        f"leads={len(leads)}  MINTED={len(minted)}  dropped={len(leads) - len(minted)}"
    )
    print("mint by sub-shape:", dict(Counter(r["subshape"] for r in minted)))
    print(
        "drop reasons:",
        dict(
            Counter(
                r["verdict"].split(":")[1] if ":" in r["verdict"] else r["verdict"]
                for r in report
                if r["verdict"] != "MINTED"
            )
        ),
    )
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
