"""Blind-authoring eval: can a model AUTHOR a CVE source-fix from the vulnerability
alone — no upstream fix supplied? This is the held-out eval for the OSS Patcher
fine-tune (the [[trace-finetuning-plan]] goal: an open-weight model that authors
fixes, so we don't pay for opus), and the direct answer to "if you just grab the
fix, what's the point?": the agent derives the fix, it doesn't copy it.

Per peer review (2026-06-12), the grader is TIERED and leakage is the enemy:
  * The model sees ONLY the vulnerability (CVE trigger + the PRE-fix source window)
    — never upstream-fix.patch, never the co-located regression test, never
    remediation language.
  * reproducer red→green is the MANDATORY behavioral gate (not run here — see the
    bundle cert; this harness scores the cheaper diff-vs-upstream signal).
  * upstream-semantically-equivalent = gold; green-but-differs = needs-review
    (the libxmp-partial class — a narrow reproducer can pass a subtly-wrong fix).

This harness reports diff-vs-upstream match per CVE. It does NOT auto-promote to
training — that requires the reproducer gate + (for differs-from-upstream) a judge.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

MODEL = os.environ.get("TRACE_AUTHOR_MODEL", "claude-opus-4-7")
_API = "https://api.anthropic.com/v1/messages"

# Remediation language must be stripped from the prompt — describing the vuln is
# fair, describing the FIX is leakage (peer trap #2).
_REMEDIATION_RE = re.compile(
    r"\b(fixed (in|by|upstream)|the fix|patched? (in|by)|adds? a (bounds|null|length) check|"
    r"resolved by|remediat\w+|commit [0-9a-f]{7,}|backport)\b",
    re.IGNORECASE,
)


def _strip_remediation(summary: str) -> str:
    # keep sentences that describe the vuln; drop ones naming the fix.
    keep = [
        s for s in re.split(r"(?<=[.])\s+", summary) if not _REMEDIATION_RE.search(s)
    ]
    return " ".join(keep).strip()


def _changed_lines(diff: str) -> tuple[set[str], set[str]]:
    """The -/+ content lines of a unified diff (normalised: strip the +/- and
    surrounding whitespace), ignoring file headers and hunk headers."""
    minus, plus = set(), set()
    for ln in diff.splitlines():
        if ln.startswith(("---", "+++", "diff ", "index ")):
            continue
        # normalise whitespace: a fix that differs from upstream only in spacing
        # (e.g. `MAX - 1` vs `MAX-1`) is semantically identical, not a divergence.
        if ln.startswith("-"):
            minus.add(re.sub(r"\s+", "", ln[1:]))
        elif ln.startswith("+"):
            plus.add(re.sub(r"\s+", "", ln[1:]))
    minus.discard("")
    plus.discard("")
    return minus, plus


def _api(prompt: str) -> str:
    body = json.dumps(
        {
            "model": MODEL,
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    req = urllib.request.Request(
        _API,
        data=body,
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    r = json.load(urllib.request.urlopen(req, timeout=180))
    return "".join(b.get("text", "") for b in r["content"])


def _git(repo: Path, *a) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({"GIT_ALLOW_PROTOCOL": "https:git:ssh", "GIT_TERMINAL_PROMPT": "0"})
    return subprocess.run(
        ["git", "-C", str(repo), *a], capture_output=True, text=True, env=env
    )


def _prefix_source(
    repo_url: str, commit: str, fpath: str, lines_span: tuple[int, int], workdir: Path
) -> str | None:
    """Fetch the PRE-fix source: the affected file at the fix commit's PARENT,
    windowed to cover ALL code hunks (peer traps #5 genuine pre-fix tree). A full
    fetch is needed when the parent isn't reachable shallowly (e.g. sourceware)."""
    from tools.trace_cli import backport_patch as bp

    try:
        repo_url = bp.clone_url(
            repo_url
        )  # validate + map cgit browse URL -> clone endpoint
    except bp.BackportError:
        return None
    repo = workdir / "src"
    repo.mkdir(exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "remote.origin.url", repo_url) if _git(
        repo, "remote", "add", "origin", repo_url
    ).returncode != 0 else None
    # Blobless tiered fetch (shared with the exporter): shallow sha-want when the
    # server allows it, else a complete blobless all-branches+tags fetch. Resolves
    # abbreviated + unadvertised-want shas without a slow full-history transfer.
    # `commit` is feed-sourced (upstream-ref.json); blobless_fetch_commit validates
    # it hex-only before any `git fetch`, so a `--upload-pack=...` value can't
    # option-inject — it returns False here and we skip the bundle.
    if not bp.blobless_fetch_commit(lambda *a: _git(repo, *a), commit):
        return None
    parent = _git(repo, "rev-parse", "-q", "--verify", f"{commit}^").stdout.strip()
    if not parent:
        return None
    blob = subprocess.run(
        ["git", "-C", str(repo), "show", f"{parent}:{fpath}"],
        capture_output=True,
        text=True,
    )
    if blob.returncode != 0:
        return None
    src = blob.stdout.splitlines()
    lo = max(0, lines_span[0] - 20)
    hi = min(len(src), lines_span[1] + 20)
    return "\n".join(src[lo:hi])


def _upstream_changed(
    bundle_dir: Path,
) -> tuple[set[str], set[str], str, tuple[int, int]]:
    """The upstream fix's changed lines + the affected file + the span covering
    ALL hunks, from the bundle's upstream-fix.patch (the ANSWER KEY for grading,
    never shown to the model). Span covers every hunk so a multi-hunk fix's code
    region (not just the first/copyright hunk) is in the window."""
    patch = (bundle_dir / "upstream-fix.patch").read_text()
    minus, plus = _changed_lines(patch)

    def _norm(p: str) -> str:
        p = p.split("\t")[0].strip()
        return p[2:] if p.startswith(("a/", "b/")) else p

    fpath = next(
        (_norm(ln[4:]) for ln in patch.splitlines() if ln.startswith("--- ")), ""
    )
    starts = [int(m) for m in re.findall(r"@@ -(\d+)", patch)] or [1]
    return minus, plus, fpath, (min(starts), max(starts))


def eval_bundle(bundle_dir: Path) -> dict:
    finding = json.loads((bundle_dir / "finding.json").read_text())
    cve = finding["cve_id"]

    # Offline path: reuse the export's cached pre_fix_source + fix_diff instead of
    # re-fetching the upstream tree. `trace export authoring` already fetched these
    # (leakage-scrubbed) and pinned them in authoring-example.json, so this
    # eliminates the "could not fetch pre-fix source" skips on large/cold upstream
    # repos AND makes the blind input IDENTICAL to the training input (codex slice B).
    cache_path = bundle_dir / "authoring-example.json"
    if cache_path.is_file():
        from tools.trace_cli.export import _scrub_summary

        c = json.loads(cache_path.read_text())
        src = c.get("pre_fix_source") or ""
        fpath = c.get("file") or ""
        fix_diff = c.get("fix_diff") or ""
        up_minus, up_plus = _changed_lines(fix_diff)
        summary = _scrub_summary(
            c.get("vuln_raw") or finding.get("summary", ""), fix_diff
        )
        src_origin = "cache"
    else:
        ur = json.loads((bundle_dir / "upstream-ref.json").read_text())
        commit = ur["upstream_fix_commits"][0]
        up_minus, up_plus, fpath, span = _upstream_changed(bundle_dir)
        summary = _strip_remediation(finding.get("summary", ""))
        with tempfile.TemporaryDirectory() as td:
            src = _prefix_source(
                commit["repo_url"], commit["commit_sha"], fpath, span, Path(td)
            )
        src_origin = "fetch"
    if not src:
        return {
            "cve": cve,
            "status": "skip",
            "reason": "could not fetch pre-fix source",
        }

    prompt = (
        "Fix this security vulnerability in C. You are given the CVE (symptom only) and the "
        "CURRENT vulnerable code. Author the MINIMAL fix — change as few lines as possible, "
        "do not rewrite. Reply with ONLY a unified diff.\n\n"
        f"# CVE\n{cve}: {summary}\n\n# Vulnerable code ({fpath})\n```c\n{src}\n```\n"
    )
    authored = _api(prompt)
    au_minus, au_plus = _changed_lines(authored)

    # diff-vs-upstream: did the authored fix make upstream's key change? Compare
    # the core changed lines (removed-by-upstream present in authored-removed,
    # added-by-upstream present in authored-added).
    removed_match = up_minus.issubset(au_minus) if up_minus else True
    added_match = up_plus.issubset(au_plus) if up_plus else True
    authored_anything = bool(au_minus or au_plus)
    if removed_match and added_match:
        verdict = "exact"  # reproduced upstream's change (the gold filter)
    elif authored_anything:
        verdict = "differs"  # authored a DIFFERENT fix — reproducer + judge
        # decide if it works / closes every path (peer: the libxmp-partial risk)
    else:
        verdict = "no-attempt"  # didn't author a change
    return {
        "cve": cve,
        "file": fpath,
        "verdict": verdict,
        "src_origin": src_origin,
        # `authored_diff` is the model candidate, fed to the Tier 2 red→green
        # gate + judge by expand_screen.py. It is NEVER a training label
        # (codex guardrail: labels stay the curated upstream fix).
        "authored_diff": authored,
        "upstream_removed": sorted(up_minus),
        "upstream_added": sorted(up_plus),
        "authored_removed": sorted(au_minus),
        "authored_added": sorted(au_plus),
    }


def main(argv: list[str]) -> int:
    bundles = [Path(p) for p in argv] or sorted(
        Path("traces/example").glob("*-backport")
    )
    results = []
    for bd in bundles:
        if not (bd / "upstream-fix.patch").is_file():
            continue
        try:
            r = eval_bundle(bd)
        except Exception as exc:  # noqa: BLE001 — eval harness, report don't crash
            r = {"cve": bd.name, "status": "error", "reason": str(exc)[:160]}
        results.append(r)
        print(f"  {r.get('cve'):<16} {r.get('verdict', r.get('status'))}")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("verdict", r.get("status"))] = (
            counts.get(r.get("verdict", r.get("status")), 0) + 1
        )
    report = {
        "model": MODEL,
        "n": len(results),
        "counts": counts,
        "results": results,
        "note": "diff-vs-upstream only; reproducer red→green is the mandatory gate (see bundle cert)",
    }
    out = Path("eval/author-blind-report.json")
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n{counts}  -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
