"""Mint NATURAL guard-condition Reviewer negatives from real vulnerable guards.

The 2026-07-16 mechanical operator-flip augmentation regressed the reviewer: naive
`>`↔`>=` flips are fragile (44% were semantic-equivalents) and taught a spurious
pattern. This mints higher-quality negatives instead: it takes the ACTUAL pre-fix
vulnerable guard from a bundle's `upstream-fix.patch` (the historical `-` line the
fix replaced) and substitutes it back into `patch.diff`, so the negative is a patch
that leaves the real, exploitable comparison in place. Non-equivalent by construction
(it is the CVE), and natural (real code, not a synthetic flip).

For each bundle it locates a (vulnerable, fixed) guard pair in upstream-fix.patch
where a comparison-bearing line was replaced by a structurally-similar fixed line,
finds the fixed line in patch.diff, and rewrites it to the vulnerable form via the
existing `trace mutate reviewer-negative --mutation condition-operator-mutation`
(count-preserving find/replace of just the differing span).

Candidates are hand-curated in CANDIDATES below (the survey found many false guards —
HTML, buffer-size decls, allocation changes — so blanket harvesting is unsafe). Each
minted negative still needs `trace replay --role reviewer` to confirm a genuine
reject; only clear non-equivalent rejects should enter the corpus.

Usage: python3 lora/mint_natural_guard_negatives.py --out-root traces/negatives-nat [--dry-run]
"""

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Hand-curated real guard-comparison CVEs. Each entry substitutes the FIXED guard in
# patch.diff back to its historical VULNERABLE form (from the CVE): `fixed_substr` is a
# unique substring of the fixed added guard line, `vuln_substr` is the real vulnerable
# comparison it replaced. Non-equivalent by construction (it is the exploit), and
# natural (real code, not a synthetic flip). Multi-line guard restructures (e.g. zlib's
# added `< extra_max` bounds clause) are deliberately excluded — they don't reduce to a
# single-line substitution.
CANDIDATES = [
    {
        "name": "CVE-2025-34451--proxychains-ng-backport",
        "fixed_substr": "ul > 255 || pl > 255",
        "vuln_substr": "proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255)",
        "note": "vuln only length-checks SOCKS5; other proxy types bypass the check",
    },
    {
        "name": "CVE-2026-7598--libssh2-backport",
        "fixed_substr": "username_len > UINT32_MAX - 27",
        "vuln_substr": "username_len + password_len + 44 <= UINT_MAX",
        "note": "vuln uses an addition that can integer-overflow before the compare",
    },
    {
        "name": "CVE-2026-33948--jq-nul-backport",
        "fixed_substr": "feof(state->current_input)",
        "vuln_substr": "state->parser != NULL",
        "note": "vuln uses the wrong NUL/EOF termination condition",
    },
    {
        "name": "CVE-2022-46908--sqlite-backport",
        "fixed_substr": "sqlite3_stricmp(zA2,",
        "vuln_substr": "sqlite3_stricmp(zA1,",
        "note": "vuln compares the wrong argument (zA1) in the allow-list check",
    },
]


def _added_line_containing(patch_diff: str, substr: str) -> str | None:
    """The unique added source line (verbatim, sans diff prefix) in patch.diff that
    contains `substr`; None if zero or >1 matches (ambiguous)."""
    hits = []
    for line in patch_diff.splitlines():
        if line.startswith("+++"):
            continue  # file header
        if line.startswith("++"):
            src = line[2:]  # embedded-patch ADDED line (the fix)
        elif line.startswith("+-"):
            continue  # embedded-patch REMOVED line (the vuln) — not source
        elif line.startswith("+"):
            src = line[1:]  # outer-added source (direct .nix edit)
        else:
            continue
        if substr in src:
            hits.append(src)
    return hits[0] if len(hits) == 1 else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-root", type=Path, default=ROOT / "traces" / "negatives-nat")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    minted = 0
    for cand in CANDIDATES:
        name = cand["name"]
        d = ROOT / "traces" / "example" / name
        if not d.exists():
            print(f"  MISS {name}: base dir absent", file=sys.stderr)
            continue
        guard_line = _added_line_containing(
            (d / "patch.diff").read_text(), cand["fixed_substr"]
        )
        if guard_line is None:
            print(
                f"  MISS {name}: fixed guard {cand['fixed_substr']!r} not uniquely "
                "in patch.diff",
                file=sys.stderr,
            )
            continue
        find, replace = cand["fixed_substr"], cand["vuln_substr"]
        cve, attr = name.split("--")[0], name.split("--")[1]
        out_dir = args.out_root / f"{cve}--{attr}--natural-guard-mint"
        print(
            f"  [{name}]  {cand['note']}\n        find={find!r} -> replace={replace!r}"
        )
        if args.dry_run:
            continue
        cmd = [
            sys.executable,
            "-m",
            "tools.trace_cli",
            "mutate",
            "reviewer-negative",
            "--base-dir",
            str(d),
            "--mutation",
            "condition-operator-mutation",
            "--guard",
            guard_line,
            "--op-from",
            find,
            "--op-to",
            replace,
            "--out-dir",
            str(out_dir),
        ]
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"    SKIP: {r.stderr.strip().splitlines()[-1:]}", file=sys.stderr)
        else:
            print(f"    MINT -> {out_dir.name}")
            minted += 1

    print(f"\nminted {minted}/{len(CANDIDATES)}", file=sys.stderr)
    print(
        "next: `trace replay --role reviewer` each; keep only clear non-equivalent "
        "rejects.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
