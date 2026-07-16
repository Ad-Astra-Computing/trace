"""Auto-mint condition-mutation Reviewer negatives from train-family bundles.

The fresh 34-fold eval (2026-07-14) showed the Reviewer-LoRA's residual accept-bias
is concentrated in SEMANTIC guard mutations: it transcribes two comparison guards
that differ only by an operator/bound and declares them "match". The training corpus
carries too few such contrastive negatives to teach char-level guard comparison
(Fable #1). This mints more, from TRAIN families only, so the fresh test fold stays
clean.

For each eligible bundle it finds an added source guard line carrying exactly one
flippable relational operator and emits a boundary mutation (`>`↔`>=`, `<`↔`<=`) via
`trace mutate reviewer-negative --mutation condition-operator-mutation`. The mutation
is count-preserving (the embedded patch still applies) but the guard is now an
off-by-one — the exact defect class the LoRA misses.

The output is a set of *candidate* negatives plus a manifest. Each candidate still
needs `trace replay --execute --role reviewer` to confirm the frontier Reviewer
genuinely rejects it (only confirmed rejects become training negatives) — this script
does NOT call any model. Run it, then validate, then hard-negative-mine.

Usage:
    python3 lora/mint_condition_negatives.py \
        --out-root traces/negatives-minted \
        --split-manifest data/splits/reviewer-v2-bigfold.json \
        [--limit N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _rel(p: Path) -> str:
    """Path relative to the repo root when possible, else absolute."""
    try:
        return str(p.resolve().relative_to(ROOT))
    except ValueError:
        return str(p)

# Boundary flips that turn a correct guard into an off-by-one. Each maps a relational
# operator to the "looser/tighter by one" variant a real defect would introduce.
_FLIPS = {">": ">=", "<": "<=", ">=": ">", "<=": "<"}

# A relational operator as a standalone comparison: surrounded by spaces, not part of
# a shift (<<, >>), arrow (->), fat-arrow (=>), or (in)equality (==, !=, <=, >=)
# unless we are deliberately matching <=/>=. We match with spaces to stay conservative.
_OP_RE = re.compile(r"(?<![<>=!-])\s(<=|>=|<|>)\s(?![=])")


def _held_out_families(manifest_path: Path) -> set[str]:
    m = json.loads(manifest_path.read_text())
    return {
        attr
        for attr, v in m.get("overrides", {}).items()
        if v.get("split") in ("test", "dev")
    }


def _is_held_out(attr: str, held: set[str]) -> bool:
    return any(attr == h or attr.startswith(h) or h.startswith(attr) for h in held)


def _added_source_lines(diff: str) -> list[str]:
    """Verbatim source content (sans diff prefix) of added lines, plain or embedded."""
    out = []
    for line in diff.splitlines():
        if line.startswith("++"):
            out.append(line[2:])
        elif line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return out


def _pick_guard(diff: str) -> tuple[str, str, str] | None:
    """Return (guard_line, op_from, op_to) for a uniquely-flippable guard, or None.

    Requires: the line reads like a guard (has if/while/for or a bound comparison),
    contains exactly one flippable operator occurrence in the whole line (so the
    mutate single-replace is unambiguous), and that exact source line appears exactly
    once among the added lines (mutate requires a unique match)."""
    added = _added_source_lines(diff)
    counts: dict[str, int] = {}
    for line in added:
        counts[line] = counts.get(line, 0) + 1
    for line in added:
        if counts[line] != 1:
            continue
        # Skip preprocessor directives — a `>` in `#define X > 8` is not a guard.
        if line.lstrip().startswith("#"):
            continue
        # Skip lines whose operator lives inside a string literal (e.g. `"/ > "`) —
        # flipping it corrupts data, not a guard. Conservative: any quote on the line.
        if '"' in line or "'" in line:
            continue
        if not re.search(r"\b(if|while|for)\b", line) and not _OP_RE.search(line):
            continue
        ops = _OP_RE.findall(line)
        if len(ops) != 1:
            continue
        op = ops[0]
        # exactly one textual occurrence of that operator token in a comparison slot
        if len(re.findall(rf"(?<![<>=!-])\s{re.escape(op)}\s(?![=])", line)) != 1:
            continue
        op_to = _FLIPS.get(op)
        if not op_to:
            continue
        # the find/replace strings mutate passes are " <op> " with surrounding spaces
        return line, f" {op} ", f" {op_to} "
    return None


def _base_attr(bundle_dir: Path) -> str:
    parts = bundle_dir.name.split("--")
    return parts[1] if len(parts) > 1 else bundle_dir.name


# Files a bundle must carry to be minted into a Reviewer negative that the frontier
# Reviewer can replay AND the reviewer exporter can turn into a training row.
_REVIEWER_READY = ("patch.diff", "upstream-fix.patch", "upstream-ref.json",
                   "patch-rationale.md", "review.md")


def _is_reviewer_ready(bundle_dir: Path) -> bool:
    return all((bundle_dir / f).exists() for f in _REVIEWER_READY)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-root", type=Path, default=ROOT / "traces" / "negatives-minted")
    ap.add_argument("--split-manifest", type=Path,
                    default=ROOT / "data" / "splits" / "reviewer-v2-bigfold.json")
    ap.add_argument("--source-root", type=Path, default=ROOT / "traces" / "example")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="report eligible candidates without invoking mutate")
    args = ap.parse_args()

    held = _held_out_families(args.split_manifest)
    candidates = []
    for d in sorted(args.source_root.glob("*/")):
        pd = d / "patch.diff"
        if not pd.exists():
            continue
        attr = _base_attr(d)
        if _is_held_out(attr, held):
            continue  # train families only — never contaminate the test fold
        if not _is_reviewer_ready(d):
            continue  # must have the full reviewer context to validate + export
        pick = _pick_guard(pd.read_text())
        if pick:
            candidates.append((d, attr, pick))

    if args.limit:
        candidates = candidates[: args.limit]

    print(f"eligible train-family condition-negative candidates: {len(candidates)}",
          file=sys.stderr)
    manifest = []
    for d, attr, (guard, op_from, op_to) in candidates:
        cve = d.name.split("--")[0]
        out_dir = args.out_root / f"{cve}--{attr}--condition-operator-mint"
        entry = {
            "base_dir": _rel(d),
            "attr": attr, "cve": cve,
            "guard": guard, "op_from": op_from.strip(), "op_to": op_to.strip(),
            "out_dir": _rel(out_dir),
        }
        if args.dry_run:
            print(f"  [dry] {cve:18} {attr:16} {op_from.strip()}->{op_to.strip()} | {guard.strip()[:70]}")
            manifest.append(entry)
            continue
        cmd = [
            sys.executable, "-m", "tools.trace_cli", "mutate", "reviewer-negative",
            "--base-dir", str(d), "--mutation", "condition-operator-mutation",
            "--guard", guard, "--op-from", op_from, "--op-to", op_to,
            "--out-dir", str(out_dir),
        ]
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  SKIP {cve}/{attr}: {r.stderr.strip().splitlines()[-1:]}", file=sys.stderr)
            entry["error"] = r.stderr.strip().splitlines()[-1:] or ["unknown"]
        else:
            print(f"  MINT {cve:18} {attr:16} {op_from.strip()}->{op_to.strip()}")
            entry["minted"] = True
        manifest.append(entry)

    args.out_root.mkdir(parents=True, exist_ok=True)
    (args.out_root / "mint-manifest.json").write_text(json.dumps(manifest, indent=2))
    minted = sum(1 for e in manifest if e.get("minted"))
    print(f"\nminted {minted}/{len(candidates)} candidates -> {args.out_root}", file=sys.stderr)
    print("next: `trace replay --execute --role reviewer` each to confirm reject "
          "(only confirmed rejects become training negatives)", file=sys.stderr)


if __name__ == "__main__":
    main()
