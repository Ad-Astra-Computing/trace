"""Reviewer-specific scorers.

The Patcher's six scorers measure patch quality. The Reviewer's
scorers measure REVIEW quality: did the verdict match the contract,
did the rationale engage the bundle, and did the verdict diverge
from a Steward-derived auto-merge signal? All three answer
load-bearing questions about whether the Reviewer is doing its job.

v0 scorer set (locked alongside `prompts/reviewer.v1.md`):

  1. **review-schema-valid** — review.md parses cleanly under the
     reviewer parser AND validates against
     `policy/reviewer-output-schema.json`. Refusal-shape invocations
     score against review-refusal.json (rule + reason).

  2. **review-evidence-cited** — `cited_evidence[]` is non-empty AND
     each entry references a real bundle artifact name (finding.json,
     upstream-ref.json, impact.json, maintainers.json, package.nix,
     patch.diff, patch-rationale.md). Catches the failure mode where
     a Reviewer issues a verdict without engaging the inputs.

  3. **review-disagreement** — informational. Scores how much the
     Reviewer's verdict diverges from a Steward-derived signal:
     * 1.0  : verdict matches what Steward would auto-decide (accept
              for clean dispatchable bundles; escalate for
              eligible-requires-human-review; reject reserved for
              Reviewer-detected defects)
     * 0.5  : verdict reasonable but not what Steward would pick
     * 0.0  : verdict directly contradicts Steward (e.g. Reviewer
              says accept when impact.exceeds_threshold=true and
              the bundle is human-review-required)
     Advisory-flagged so it never gates; included for cohort
     comparisons where a Reviewer that always agrees is suspicious.

The Reviewer scorers run AGAINST a (bundle_dir, reviewer_invocation)
pair, mirroring the Patcher scorer entry shape. They live alongside
the Patcher scorers in `agents/scorers/`; the runner pairs each set
with the matching role.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.reviewer import (
    ReviewerOutputMalformed,
    ReviewerParseResult,
    parse_reviewer_output,
)
from agents.scorers.types import SCORER_VERSION, ScorerResult


CANONICAL_BUNDLE_ARTIFACTS: tuple[str, ...] = (
    "finding.json",
    "upstream-ref.json",
    "impact.json",
    "maintainers.json",
    "package.nix",
    "patch.diff",
    "patch-rationale.md",
)


def reviewer_scorer_names() -> tuple[str, ...]:
    """The locked Reviewer scorer names, in canonical order."""
    return (
        "review-schema-valid",
        "review-evidence-cited",
        "review-disagreement",
    )


# ─── shared helpers ────────────────────────────────────────────────────────


def _outputs_kind(invocation: dict[str, Any]) -> str:
    """Detect whether the reviewer invocation produced a review or a refusal."""
    out_paths = {o["path"] for o in invocation.get("outputs") or []}
    if "review.md" in out_paths:
        return "review"
    if "review-refusal.json" in out_paths:
        return "refusal"
    return "unknown"


def _load_review_md(bundle_dir: Path) -> ReviewerParseResult | None:
    """Read review.md and parse; return None if missing OR malformed."""
    p = bundle_dir / "review.md"
    if not p.is_file():
        return None
    raw = (
        "=== BEGIN review.md ===\n"
        + p.read_text().rstrip("\n")
        + "\n=== END review.md ==="
    )
    try:
        return parse_reviewer_output(raw)
    except ReviewerOutputMalformed:
        return None


# ─── 1. review-schema-valid ────────────────────────────────────────────────


class ReviewSchemaValidScorer:
    name = "review-schema-valid"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return self._score_refusal(bundle_dir)
        if kind != "review":
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"reviewer invocation outputs are not in the canonical set; got {sorted({o['path'] for o in invocation.get('outputs') or []})}",
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review.md missing or fails strict parser",
            )
        # Schema check on the parsed shape.
        try:
            from jsonschema import Draft202012Validator
            schema_path = Path(__file__).resolve().parents[2] / "policy" / "reviewer-output-schema.json"
            schema = json.loads(schema_path.read_text())
            errors = list(Draft202012Validator(schema).iter_errors(parsed.to_schema_dict()))
            if errors:
                return ScorerResult(
                    self.name, self.version,
                    applies=True, advisory=False, score=0.0,
                    notes=f"review.md parses but fails reviewer-output-schema: {errors[0].message}",
                    details={"first_schema_error": errors[0].message},
                )
        except ImportError:
            # jsonschema is in the dev shell; missing implies an
            # unusual environment. Treat as informational rather than
            # a fail.
            pass

        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=1.0,
            notes=f"review.md parses cleanly and matches schema; verdict={parsed.verdict}",
            details={"verdict": parsed.verdict, "n_findings": len(parsed.findings)},
        )

    def _score_refusal(self, bundle_dir: Path) -> ScorerResult:
        ref_path = bundle_dir / "review-refusal.json"
        if not ref_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review-refusal.json missing",
            )
        try:
            body = json.loads(ref_path.read_text())
        except json.JSONDecodeError as exc:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"review-refusal.json invalid JSON: {exc}",
            )
        if not (isinstance(body, dict) and "rule" in body and "reason" in body):
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review-refusal.json missing rule or reason",
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=1.0,
            notes=f"review-refusal.json well-formed; rule={body['rule']}",
            details={"rule": body["rule"]},
        )


# ─── 2. review-evidence-cited ──────────────────────────────────────────────


class ReviewEvidenceCitedScorer:
    name = "review-evidence-cited"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="reviewer refusal: evidence-cited is not applicable",
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None or parsed.kind != "review":
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review.md missing or fails strict parser",
            )

        cited = parsed.cited_evidence
        if not cited:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="cited_evidence is empty",
            )

        recognised = []
        unrecognised = []
        for entry in cited:
            artifact = entry.split(":", 1)[0]
            if artifact in CANONICAL_BUNDLE_ARTIFACTS:
                recognised.append(entry)
            else:
                unrecognised.append(entry)
        score = len(recognised) / len(cited)
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=score,
            notes=(
                f"{len(recognised)}/{len(cited)} citations name canonical "
                f"bundle artifacts; unrecognised: {unrecognised or '(none)'}"
            ),
            details={
                "cited_total": len(cited),
                "recognised_count": len(recognised),
                "unrecognised": unrecognised,
            },
        )


# ─── 3. review-disagreement (advisory) ─────────────────────────────────────


class ReviewDisagreementScorer:
    name = "review-disagreement"
    version = SCORER_VERSION
    advisory = True  # informational: never gates

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=True, score=None,
                notes="reviewer refusal: disagreement signal is not applicable",
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None or parsed.kind != "review":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=True, score=None,
                notes="review.md missing or unparseable; cannot compare to Steward signal",
            )

        # Steward-derived signal: read bundle.json + upstream-ref.json +
        # impact.json. The signal is a coarse classifier of what
        # Steward would do absent a Reviewer verdict.
        steward_signal = _derive_steward_signal(bundle_dir)
        verdict = parsed.verdict
        if steward_signal is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=True, score=None,
                notes="Steward signal not derivable from bundle artifacts",
            )

        # Score by alignment.
        if steward_signal == verdict:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=True, score=1.0,
                notes=f"verdict={verdict!r} matches Steward signal {steward_signal!r}",
                details={"verdict": verdict, "steward_signal": steward_signal},
            )
        if (steward_signal, verdict) == ("accept", "escalate") or \
           (steward_signal, verdict) == ("escalate", "accept"):
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=True, score=0.5,
                notes=f"verdict={verdict!r} adjacent to Steward signal {steward_signal!r}",
                details={"verdict": verdict, "steward_signal": steward_signal},
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=True, score=0.0,
            notes=f"verdict={verdict!r} contradicts Steward signal {steward_signal!r}",
            details={"verdict": verdict, "steward_signal": steward_signal},
        )


def _derive_steward_signal(bundle_dir: Path) -> str | None:
    """Coarse classifier: what would Steward auto-decide for this bundle
    absent a Reviewer verdict? Returns one of `accept`, `reject`,
    `escalate`, or None when not derivable."""
    bundle_path = bundle_dir / "bundle.json"
    upstream_ref_path = bundle_dir / "upstream-ref.json"
    if not (bundle_path.is_file() and upstream_ref_path.is_file()):
        return None
    try:
        bundle = json.loads(bundle_path.read_text())
        upstream_ref = json.loads(upstream_ref_path.read_text())
    except json.JSONDecodeError:
        return None
    kind = bundle.get("kind")
    verdict = (upstream_ref.get("eligibility") or {}).get("verdict") or ""
    # Reject if dispatch-guarded.
    if kind == "advisory-only":
        return "reject"
    if verdict.startswith("ineligible-"):
        return "reject"
    # Escalate if forced into human-review-required by impact / verdict.
    if kind == "human-review-required":
        return "escalate"
    if verdict == "eligible-requires-human-review":
        return "escalate"
    # Otherwise accept (clean auto-merge candidate).
    if kind == "auto-merge" and verdict == "eligible":
        return "accept"
    return None


__all__ = [
    "CANONICAL_BUNDLE_ARTIFACTS",
    "ReviewDisagreementScorer",
    "ReviewEvidenceCitedScorer",
    "ReviewSchemaValidScorer",
    "reviewer_scorer_names",
]
