"""Scorer #2: upstream-ref compliance.

The patch-rationale.md "## Upstream reference" section MUST cite, at
minimum:

  * upstream-ref.json.target_version (or its `tag` field if distinct)
  * every entry in upstream-ref.json.upstream_fix_commits[].commit_sha

Score = fraction of expected citations actually present in the
rationale's text. 1.0 iff all expected references appear (substring
match, case-insensitive on tags; case-insensitive prefix match on
commit shas to allow short-sha citations).

Refusal-shape invocations: applies=False (refusals don't carry a
rationale to check).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


class UpstreamRefComplianceScorer:
    name = "upstream-ref-compliance"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        out_paths = {o["path"] for o in invocation.get("outputs") or []}
        if "refusal.json" in out_paths:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="patcher invocation produced a refusal; "
                      "upstream-ref compliance is not applicable",
            )

        rat_path = bundle_dir / "patch-rationale.md"
        upstream_ref_path = bundle_dir / "upstream-ref.json"
        if not rat_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="patch-rationale.md not on disk",
            )
        if not upstream_ref_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="upstream-ref.json missing from bundle; nothing to compare against",
            )

        rationale = rat_path.read_text()
        upstream_ref = json.loads(upstream_ref_path.read_text())

        expected_tokens: list[tuple[str, str]] = []  # (label, search-string)
        target = upstream_ref.get("target_version")
        tag = upstream_ref.get("tag")
        if isinstance(target, str) and target:
            expected_tokens.append(("target_version", target))
        if isinstance(tag, str) and tag and tag != target:
            expected_tokens.append(("tag", tag))
        for fix in upstream_ref.get("upstream_fix_commits") or []:
            sha = fix.get("commit_sha")
            if isinstance(sha, str) and sha:
                expected_tokens.append(("commit_sha", sha))

        if not expected_tokens:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="upstream-ref.json carries no target_version, tag, or "
                      "upstream_fix_commits to check against",
            )

        upstream_section = _extract_section(rationale, "## Upstream reference")
        # Citations may legitimately appear elsewhere; check the whole rationale
        # but report whether the upstream section itself contained them.
        rationale_lower = rationale.lower()
        section_lower = (upstream_section or "").lower()

        present_anywhere: list[dict[str, Any]] = []
        present_in_section: list[dict[str, Any]] = []
        absent: list[dict[str, Any]] = []
        for label, token in expected_tokens:
            tok_lower = token.lower()
            anywhere = tok_lower in rationale_lower
            # Commit shas are matched by prefix to allow 7-char abbreviations.
            if not anywhere and label == "commit_sha":
                anywhere = any(
                    tok_lower.startswith(line.strip()) and len(line.strip()) >= 7
                    for line in rationale_lower.split()
                )
            in_section = anywhere and tok_lower in section_lower
            entry = {"label": label, "token": token}
            (present_anywhere if anywhere else absent).append(entry)
            if in_section:
                present_in_section.append(entry)

        score = len(present_anywhere) / len(expected_tokens)
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=score,
            notes=(
                f"{len(present_anywhere)}/{len(expected_tokens)} expected "
                f"upstream-ref citations present (target/tag/commit shas)"
            ),
            details={
                "expected_count": len(expected_tokens),
                "present_anywhere_count": len(present_anywhere),
                "present_in_section_count": len(present_in_section),
                "absent": absent,
            },
        )


def _extract_section(rationale: str, heading: str) -> str | None:
    """Return the text from `heading` up to the next level-2 heading."""
    lines = rationale.splitlines()
    out: list[str] = []
    in_section = False
    for line in lines:
        if line.strip() == heading:
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section:
            out.append(line)
    if not in_section:
        return None
    return "\n".join(out).strip()
