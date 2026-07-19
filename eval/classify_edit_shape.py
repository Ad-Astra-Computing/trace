"""Classify the EDIT SHAPE of a fix diff — condition-fold vs guard-clip vs guard-add.

The authoring-LoRA over-produces GUARD-CLIPS (insert a separate clamp/guard block) where
many upstream fixes CONDITION-FOLD (refine an existing comparison inline). The samplability
diagnostic (DECISIONS 2026-07-17) showed bzip2's bound-guard and pyjwt's security-guard are
zero-mass — training-data-gated. Before harvesting shape-targeted data, this measures the
shape distribution of the corpus we already train on (Fable's Step 0): if it is fold-poor,
the shape-stratified-SFT hypothesis is live; if fold-rich, it is probably already dead.

Shapes (labelled per hunk; the patch is labelled by its largest non-context hunk):
  - condition-fold      : a paired (−,+) conditional line, same condition modified in place
      sub: operator-refine | bound-arith-fold | conjunct-add | operand-replace
  - guard-clip          : net-added `if`/`unless` whose body clamps (assign/return/goto/break/continue)
  - security-guard-add  : net-added guard whose body RAISES/errors on a validity predicate (pyjwt class)
  - multi-hunk-refactor / other : everything else (excluded from a stratified batch)

Pure functions + a canary-calibrated census when run as __main__.
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path

_CTRL = re.compile(r"\b(if|elif|while|for|unless)\b|[?]")
_CMP = re.compile(r"(<=|>=|==|!=|<|>|&&|\|\||\band\b|\bor\b)")
_CONJ = re.compile(r"(&&|\|\||\band\b|\bor\b)")
_RAISE = re.compile(r"\b(raise|throw|abort|panic|BUG|error|err|fatal)\b|return\s+(-?\w*E[A-Z_]+|NULL|false|-1)", re.I)
_CLAMP = re.compile(r"=\s*[\w\[\]\.\-> ]+;?\s*$|\b(return|goto|break|continue)\b")
_ASSIGN = re.compile(r"[\w\[\]\.\->]+\s*=\s*[^=]")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


_IMPORT = re.compile(r"^\s*(import|from|use|require|require_relative|#include|#import|#define|"
                     r"#if|#ifdef|#ifndef|#endif|#pragma|package|using|typedef)\b")


def _is_comment(s: str) -> bool:
    t = s.strip()
    return t.startswith(("#", "//", "*", "/*", "--", '"""', "'''")) or t == ""


def _is_noncode(s: str) -> bool:
    """Comment/blank OR a non-executable line (import/include/preprocessor/decl) — excluded
    from SHAPE candidacy so a fix that merely adds an `#include`/import doesn't read as a
    fold/guard. Precision fix for the ≥90%-agreement bar (DECISIONS 2026-07-17)."""
    return _is_comment(s) or bool(_IMPORT.match(s))


def _tok(s: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[<>=!&|]+", s))


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tok(a), _tok(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _hunks(diff: str) -> list[tuple[list[str], list[str]]]:
    """Return [(removed, added)] code lines per hunk (comments/blank dropped)."""
    out, rem, add = [], [], []
    in_hunk = False

    def flush():
        nonlocal rem, add
        if rem or add:
            out.append((rem, add))
        rem, add = [], []

    for ln in diff.splitlines():
        if ln.startswith("@@"):
            flush()
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if ln.startswith("+") and not ln.startswith("+++"):
            body = ln[1:]
            if not _is_noncode(body):
                add.append(body)
        elif ln.startswith("-") and not ln.startswith("---"):
            body = ln[1:]
            if not _is_noncode(body):
                rem.append(body)
        elif ln and ln[0] not in " ":
            # left the hunk region (e.g. diff --git / index) — flush
            flush()
            in_hunk = ln.startswith("@@")
    flush()
    return out


def _fold_subshape(rem: str, add: str) -> str:
    r, a = _norm(rem), _norm(add)
    if _CONJ.search(a) and not _CONJ.search(r):
        return "conjunct-add"
    r_ops, a_ops = _CMP.findall(r), _CMP.findall(a)
    if r_ops and a_ops and r_ops != a_ops and _tok(r) - _CMP_TOKENS == _tok(a) - _CMP_TOKENS:
        return "operator-refine"
    # arithmetic term added in a bound operand (extra_max -> extra_max - len; X -> X - 1)
    if re.search(r"[-+*/]", a) and _jaccard(r, a) >= 0.5 and len(_tok(a) - _tok(r)) >= 1:
        return "bound-arith-fold"
    return "operand-replace"


_CMP_TOKENS = {"<", ">", "<=", ">=", "==", "!=", "&&", "||"}


def classify_hunk(rem: list[str], add: list[str]) -> tuple[str, str]:
    # 1. condition-fold: a paired (removed, added) conditional line, same condition modified
    sm = difflib.SequenceMatcher(a=[_norm(x) for x in rem], b=[_norm(x) for x in add])
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "replace":
            continue
        for ri in range(i1, i2):
            for aj in range(j1, j2):
                r, a = rem[ri], add[aj]
                cond = (_CTRL.search(r) or _CMP.search(r)) and (_CTRL.search(a) or _CMP.search(a))
                if cond and _jaccard(r, a) >= 0.5:
                    return "condition-fold", _fold_subshape(r, a)
    # 2. net-added guard (no paired removal) — clip vs security-guard-add
    if add and not rem:
        joined = " ".join(add)
        # a guard REQUIRES an added control keyword (if/while/...) — else it is not a guard,
        # it is an insertion (decl, call, assignment) and classified "other".
        if any(_CTRL.search(a) for a in add):
            if _RAISE.search(joined):
                return "security-guard-add", "raise-on-predicate"
            if _CLAMP.search(joined):
                return "guard-clip", "clamp-body"
    return "other", ""


def classify_diff(diff: str) -> dict:
    """Label the whole diff by its largest non-context hunk (most changed lines)."""
    hunks = _hunks(diff)
    if not hunks:
        return {"shape": "other", "subshape": "", "n_hunks": 0}
    labels = [(len(r) + len(a), classify_hunk(r, a)) for r, a in hunks]
    labels.sort(key=lambda x: -x[0])
    shape, sub = labels[0][1]
    return {"shape": shape, "subshape": sub, "n_hunks": len(hunks),
            "per_hunk": [lab for _, lab in labels]}


# ── canary-calibrated census ──────────────────────────────────────────────────
def _census() -> None:
    import json
    ROOT = Path(__file__).resolve().parents[1]
    canary = ROOT / "exports/authoring-lora/authoring-canary.jsonl"
    train = ROOT / "exports/authoring-lora/authoring.train.jsonl"
    CAN = {"CVE-2022-37434": "zlib(expect condition-fold)",
           "CVE-2026-42250": "bzip2(expect condition-fold/bound OR guard)",
           "CVE-2024-47081": "requests(?)", "CVE-2026-48526": "pyjwt(expect security-guard-add)"}
    print("=== CANARY CALIBRATION ===")
    for l in canary.read_text().splitlines():
        if not l.strip():
            continue
        r = json.loads(l); cve = (r.get("provenance") or {}).get("cve_id", "")
        if cve in CAN:
            ref = next((m["content"] for m in r["messages"] if m["role"] == "assistant"), "")
            c = classify_diff(ref)
            print(f"  {CAN[cve]:40} -> {c['shape']}/{c['subshape']}")
    print("\n=== TRAIN CORPUS SHAPE CENSUS ===")
    from collections import Counter
    cnt = Counter()
    for l in train.read_text().splitlines():
        if not l.strip():
            continue
        r = json.loads(l)
        ref = next((m["content"] for m in r["messages"] if m["role"] == "assistant"), "")
        cnt[classify_diff(ref)["shape"]] += 1
    total = sum(cnt.values())
    for shape, n in cnt.most_common():
        print(f"  {shape:20} {n:3}  ({n/total:.0%})")
    fold = cnt.get("condition-fold", 0)
    print(f"\n  condition-fold share: {fold}/{total} = {fold/total:.0%} "
          f"-> hypothesis {'LIVE (fold-poor)' if fold/total < 0.35 else 'likely dead (fold-rich)'}")


if __name__ == "__main__":
    _census()
