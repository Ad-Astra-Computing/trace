"""Scorer #1: schema-valid output.

Binary pass/fail. Score=1.0 iff:
  * patch.diff parses as a unified diff (at least one '--- ' / '+++ '
    file header pair AND at least one hunk header '@@')
  * patch-rationale.md contains the five SPEC §4 mandatory level-2
    headings, in the contracted order, with no level-1 heading

For Patcher refusal-shape invocations, the equivalent check runs against
refusal.json (the body must contain `rule` and `reason`). Score=1.0 iff
the file parses as JSON with both keys.

Rationale-completeness folds into this scorer (per MODEL_EVAL_PLAN.md
amendment).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


REQUIRED_RATIONALE_HEADINGS = (
    "## Upstream reference",
    "## Why this version",
    "## Why minimal",
    "## Alternatives rejected",
    "## Downstream risk",
)


class SchemaValidScorer:
    name = "schema-valid"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        outputs = invocation.get("outputs") or []
        out_paths = {o["path"] for o in outputs}

        # Refusal path
        if "refusal.json" in out_paths:
            return self._score_refusal(bundle_dir)

        # Patch path
        if {"patch.diff", "patch-rationale.md"} - out_paths:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    "patch invocation missing required output files; "
                    f"declared outputs = {sorted(out_paths)}"
                ),
                details={"missing_required_outputs": True},
            )
        return self._score_patch(bundle_dir)

    def _score_patch(self, bundle_dir: Path) -> ScorerResult:
        diff_path = bundle_dir / "patch.diff"
        rat_path = bundle_dir / "patch-rationale.md"
        if not diff_path.is_file() or not rat_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="patch.diff or patch-rationale.md not on disk",
            )
        diff = diff_path.read_text()
        rationale = rat_path.read_text()

        diff_ok, diff_reason = _looks_like_unified_diff(diff)
        rat_ok, rat_reason = _rationale_has_required_headings(rationale)

        if diff_ok and rat_ok:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=1.0,
                notes="patch.diff parses as a unified diff and patch-rationale.md "
                      "has all five required headings in order",
                details={"diff_ok": True, "rationale_ok": True},
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=0.0,
            notes=f"diff: {diff_reason}; rationale: {rat_reason}",
            details={
                "diff_ok": diff_ok, "diff_reason": diff_reason,
                "rationale_ok": rat_ok, "rationale_reason": rat_reason,
            },
        )

    def _score_refusal(self, bundle_dir: Path) -> ScorerResult:
        ref_path = bundle_dir / "refusal.json"
        if not ref_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="refusal.json declared in invocation but not on disk",
            )
        try:
            body = json.loads(ref_path.read_text())
        except json.JSONDecodeError as exc:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"refusal.json is not valid JSON: {exc}",
            )
        if not isinstance(body, dict):
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="refusal.json must be a JSON object",
            )
        missing = [k for k in ("rule", "reason") if k not in body]
        if missing:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"refusal.json missing required keys: {missing}",
                details={"missing_keys": missing},
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=1.0,
            notes="refusal.json has rule and reason",
            details={"rule": body["rule"], "reason_len": len(str(body["reason"]))},
        )


def _looks_like_unified_diff(text: str) -> tuple[bool, str]:
    if not text.strip():
        return False, "empty diff"
    has_minus = any(line.startswith("--- ") for line in text.splitlines())
    has_plus = any(line.startswith("+++ ") for line in text.splitlines())
    has_hunk = any(line.startswith("@@") for line in text.splitlines())
    if not (has_minus and has_plus):
        return False, "missing '--- ' / '+++ ' file header pair"
    if not has_hunk:
        return False, "missing '@@' hunk header"
    return True, "ok"


def _rationale_has_required_headings(rationale: str) -> tuple[bool, str]:
    lines = rationale.splitlines()
    seen: dict[str, int] = {}
    for i, line in enumerate(lines):
        h = line.strip()
        if h in REQUIRED_RATIONALE_HEADINGS and h not in seen:
            seen[h] = i
    missing = [h for h in REQUIRED_RATIONALE_HEADINGS if h not in seen]
    if missing:
        return False, f"missing required headings: {missing}"
    positions = [seen[h] for h in REQUIRED_RATIONALE_HEADINGS]
    if positions != sorted(positions):
        return False, "required headings out of contracted order"
    for line in lines:
        if line.startswith("# ") and not line.startswith("## "):
            return False, "level-1 heading present (forbidden by SPEC §4)"
    return True, "ok"
