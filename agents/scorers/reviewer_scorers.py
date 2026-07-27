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
from hashlib import sha256
from pathlib import Path
from typing import Any

from agents.reviewer import (
    ReviewerOutputMalformed,
    ReviewerParseResult,
    VALID_EQUIVALENCE_VALUES,
    parse_equivalence_verdict,
    parse_reviewer_output,
)
from agents.scorers.adaptation_oracle import get_oracle
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

# Optional artifacts that are canonical ONLY when actually present in the bundle
# (so a bundle that doesn't have one gets no credit for citing it). Maps the
# filename to a no-op presence check at scoring time. Source-backport bundles
# carry upstream-fix.patch (the ground-truth diff the Reviewer verifies against).
_OPTIONAL_BUNDLE_ARTIFACTS: tuple[str, ...] = (
    "upstream-fix.patch",
)


def reviewer_scorer_names() -> tuple[str, ...]:
    """The locked Reviewer scorer names, in canonical order.

    NOTE: `review-adaptation-equivalence` (below) is deliberately NOT in this
    tuple. This tuple is the locked canonical composite paired with
    `prompts/reviewer.v1.md`; it runs against every reviewer invocation
    regardless of bundle shape. The adaptation-equivalence scorer only
    applies to the narrow adaptation lane (source-context/ + preflight.json
    with applies_verbatim != true) AND only for CVEs with a registered
    ground-truth oracle (`agents/scorers/adaptation_oracle.py`) — most
    bundles will never trigger it. It is a cohort-eval scorer consumed by
    name (e.g. by the aggregator / a dedicated eval command), not part of
    the per-invocation canonical set.
    """
    return (
        "review-schema-valid",
        "review-evidence-cited",
        "review-cross-family-attestation",
        "review-patch-comparison-present",
        "review-disagreement",
    )


def _model_id_to_family(model_id: str) -> str | None:
    """Coarse mapping of a model_id to a family label.

    Mirrors `tools/trace_cli/execute.py:_model_id_family` (the
    deterministic check used to enforce the cross-family rule before
    any model call). Inlined here so the scorer module has no tool→
    agent dependency. Both surfaces must stay in sync; if a new family
    enters either, update both.
    """
    if not model_id:
        return None
    if model_id.startswith("claude-opus"):
        return "anthropic-opus"
    if model_id.startswith("claude-sonnet"):
        return "anthropic-sonnet"
    if model_id.startswith("claude-haiku"):
        return "anthropic-haiku"
    if model_id.startswith("claude-"):
        return "anthropic-other"
    if model_id.startswith("gpt-"):
        return "openai-gpt"
    return None


def _patcher_family_from_replay(bundle_dir: Path) -> str | None:
    """Read replay.json and return the family of the most-recent patcher
    invocation. Returns None when no patcher invocation is recorded or
    the replay is unparseable."""
    rj = bundle_dir / "replay.json"
    if not rj.is_file():
        return None
    try:
        replay = json.loads(rj.read_text())
    except json.JSONDecodeError:
        return None
    if not isinstance(replay, dict):
        return None
    roles = replay.get("roles", [])
    if not isinstance(roles, list):
        return None
    # Tolerant of a malformed replay: non-dict role entries, a non-list/empty
    # invocations, or a non-dict last invocation are skipped rather than
    # crashing on .get() (the scorer must fail closed, not traceback).
    for role in roles:
        if not isinstance(role, dict) or role.get("role") != "patcher":
            continue
        invs = role.get("invocations")
        if not isinstance(invs, list) or not invs:
            continue
        last = invs[-1]
        if not isinstance(last, dict):
            continue
        model = last.get("model")
        model_id = model.get("model_id") if isinstance(model, dict) else None
        return _model_id_to_family(model_id or "")
    return None


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

        # An optional artifact counts as canonical only if it actually exists in
        # this bundle (e.g. upstream-fix.patch on source-backport bundles) — a
        # version-bump bundle gets no credit for citing a non-existent artifact.
        recognised_set = set(CANONICAL_BUNDLE_ARTIFACTS) | {
            name for name in _OPTIONAL_BUNDLE_ARTIFACTS if (bundle_dir / name).is_file()
        }
        recognised = []
        unrecognised = []
        for entry in cited:
            # Colon-separated: "patch.diff:CVE-123.patch", "patch-rationale.md:## Section"
            artifact = entry.split(":", 1)[0]
            if artifact not in recognised_set:
                # Dot-path field citation: "finding.json.summary",
                # "upstream-ref.json.eligibility.patch_strategy=source-backport"
                for name in recognised_set:
                    if entry.startswith(name + "."):
                        artifact = name
                        break
            if artifact in recognised_set:
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


# ─── 3. review-cross-family-attestation (non-advisory, low-weight) ────────


class ReviewCrossFamilyAttestationScorer:
    """Verifies the Reviewer's cross-family attestation block against
    deterministic ground truth.

    The block contains THREE claims:
      * `reviewer_family`            — model's claim about itself
      * `patcher_family_observed`    — model's claim about the Patcher
      * `rule_honored`               — model's claim about (1)≠(2)

    All three are model-emitted. Ground truth is deterministic:
      * recorded_reviewer_family = family(invocation.model.model_id)
      * recorded_patcher_family  = family(replay.json patcher's model_id)
      * recorded_rule_honored    = (recorded_reviewer_family !=
                                    recorded_patcher_family)

    The earlier shape of this scorer only verified
    `patcher_family_observed`. Two wget2 reviewer runs (2026-05-13)
    surfaced the gap: run 1's Reviewer emitted
    `patcher_family_observed: openai-gpt` (against an Anthropic Opus
    Patcher — correctly caught), but run 2's emitted plausible-looking
    `patcher_family_observed: anthropic-opus` paired with the
    fabricated claim `reviewer_family: anthropic-claude, rule_honored:
    false` (the Reviewer was anthropic-sonnet; routing-config.json
    genuinely paired Opus + Sonnet families, so rule_honored should
    be true). That fabrication slipped through unverified.

    Non-advisory: any fabricated field is real trust-erosion evidence.

    Score:
      1.0 — all three claims match deterministic ground truth.
      0.0 — at least one fabricated claim.
      None+applies=False — refusal-shape invocations, OR replay.json
            has no patcher invocation, OR the cross_family block is
            missing/unparseable, OR the invocation lacks a model_id
            (parser failures should already have flagged it via
            review-schema-valid).
    """
    name = "review-cross-family-attestation"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="reviewer refusal: cross-family attestation is not applicable",
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None or parsed.kind != "review" or parsed.cross_family is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="review.md missing / malformed / lacks cross-family attestation",
            )

        recorded_patcher = _patcher_family_from_replay(bundle_dir)
        if recorded_patcher is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="replay.json has no patcher invocation; cannot verify attestation",
            )

        reviewer_model_id = (invocation.get("model") or {}).get("model_id") or ""
        recorded_reviewer = _model_id_to_family(reviewer_model_id)
        if recorded_reviewer is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=(
                    f"reviewer invocation has no resolvable model family "
                    f"(model_id={reviewer_model_id!r}); cannot verify attestation"
                ),
            )

        recorded_rule_honored = recorded_reviewer != recorded_patcher

        cf = parsed.cross_family
        observed_reviewer = cf.reviewer_family
        observed_patcher = cf.patcher_family_observed
        observed_rule_honored = cf.rule_honored

        # Each claim is verified independently; the score is 1.0 only
        # if all three match. Any fabrication drops to 0.0 and the
        # details enumerate which specific fields diverged so cohort
        # reports can distinguish "Patcher mis-identified" from
        # "Reviewer mis-identified itself" from "rule-honored lie."
        mismatches: list[str] = []
        if observed_reviewer != recorded_reviewer:
            mismatches.append("reviewer_family")
        if observed_patcher != recorded_patcher:
            mismatches.append("patcher_family_observed")
        if observed_rule_honored != recorded_rule_honored:
            mismatches.append("rule_honored")

        details = {
            "reviewer_family_observed": observed_reviewer,
            "reviewer_family_recorded": recorded_reviewer,
            "patcher_family_observed": observed_patcher,
            "patcher_family_recorded": recorded_patcher,
            "rule_honored_observed": observed_rule_honored,
            "rule_honored_recorded": recorded_rule_honored,
            "fabricated_fields": mismatches,
            "match": not mismatches,
        }
        if not mismatches:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=1.0,
                notes=(
                    f"attestation matches on all three fields: reviewer_family="
                    f"{recorded_reviewer!r}, patcher_family_observed="
                    f"{recorded_patcher!r}, rule_honored={recorded_rule_honored}"
                ),
                details=details,
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=0.0,
            notes=(
                f"attestation FABRICATED on {', '.join(mismatches)}: "
                f"recorded (reviewer_family={recorded_reviewer!r}, "
                f"patcher_family={recorded_patcher!r}, "
                f"rule_honored={recorded_rule_honored}) vs observed "
                f"(reviewer_family={observed_reviewer!r}, "
                f"patcher_family_observed={observed_patcher!r}, "
                f"rule_honored={observed_rule_honored})"
            ),
            details=details,
        )


# ─── 4. review-patch-comparison-present (source-backport gate) ────────────


class ReviewPatchComparisonPresentScorer:
    """For source-backport bundles, require a `## Patch comparison` section.

    Source-backport reviews (v5+ prompt) must contain a `## Patch comparison`
    section that quotes the actual +/- lines from patch.diff and
    upstream-fix.patch side-by-side. This is the structural enforcement of
    check 0: a review without it is schema-invalid.

    Applies only when upstream-ref.json.eligibility.patch_strategy ==
    "source-backport". Non-source-backport bundles always score applies=False.

    Score:
      1.0 — source-backport and ## Patch comparison section is present
      0.0 — source-backport and ## Patch comparison section is absent
      None+applies=False — not a source-backport, or review.md missing
    """
    name = "review-patch-comparison-present"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="reviewer refusal: patch-comparison check is not applicable",
            )

        # Only applies to source-backport bundles.
        upstream_ref_path = bundle_dir / "upstream-ref.json"
        if not upstream_ref_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="upstream-ref.json missing; cannot determine patch_strategy",
            )
        try:
            upstream_ref = json.loads(upstream_ref_path.read_text())
        except json.JSONDecodeError:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="upstream-ref.json invalid JSON",
            )
        patch_strategy = (upstream_ref.get("eligibility") or {}).get("patch_strategy")
        if patch_strategy != "source-backport":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=f"patch_strategy={patch_strategy!r}; scorer only applies to source-backport",
            )

        # Adaptation lane (reviewer.v10): the contract REPLACES `## Patch
        # comparison` with `## Equivalence assessment` (line-level matching is
        # not meaningful when the fix does not apply verbatim). A contract-
        # compliant v10 review omits `## Patch comparison`, so this scorer must
        # abstain here rather than score a false 0.0 that depresses the cohort
        # rate. The adaptation-equivalence scorer covers this lane instead.
        if _is_adaptation_lane(bundle_dir):
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=(
                    "adaptation lane (applies_verbatim!=true): '## Patch comparison' "
                    "is replaced by '## Equivalence assessment'; scored by "
                    "review-adaptation-equivalence instead"
                ),
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None or parsed.kind != "review":
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review.md missing or fails strict parser",
            )

        if parsed.patch_comparison_raw is None:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    "source-backport review is missing required '## Patch comparison' "
                    "section (v5+ contract: check 0 must be an explicit evidence record)"
                ),
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=1.0,
            notes=(
                f"'## Patch comparison' section present "
                f"({len(parsed.patch_comparison_raw)} chars)"
            ),
            details={"patch_comparison_length": len(parsed.patch_comparison_raw)},
        )


# ─── 4b. review-adaptation-equivalence (adaptation-lane cohort scorer) ────


def _is_adaptation_lane(bundle_dir: Path) -> bool:
    """A bundle is in the ADAPTATION lane iff it is a SOURCE-BACKPORT that
    carries a non-empty source-context/ dir AND `applies_verbatim` is anything
    other than the literal True.

    This MUST match the executor's routing in `tools/trace_cli/execute.py`,
    which enters this lane only inside the `patch_strategy == 'source-backport'`
    branch, and there fails closed to the higher-scrutiny adaptation lane for
    every `applies_verbatim` value except a successfully-parsed literal True:
    a missing preflight.json, unparseable JSON, a non-object document, or a
    missing/false/non-boolean `applies_verbatim` key all route to the
    adaptation lane. Only `preflight.json` that parses to an object whose
    `applies_verbatim` is exactly True selects the verbatim lane. A non-source-
    backport bundle (e.g. a version bump) is never the adaptation lane even if
    it happens to retain a source-context/ dir."""
    upstream_ref_path = bundle_dir / "upstream-ref.json"
    if not upstream_ref_path.is_file():
        return False
    try:
        upstream_ref = json.loads(upstream_ref_path.read_text())
    except json.JSONDecodeError:
        return False
    if not isinstance(upstream_ref, dict):
        return False
    patch_strategy = (upstream_ref.get("eligibility") or {}).get("patch_strategy")
    if patch_strategy != "source-backport":
        return False
    source_context = bundle_dir / "source-context"
    if not source_context.is_dir():
        return False
    if not any(p.is_file() for p in source_context.rglob("*")):
        return False
    applies_verbatim: Any = None
    preflight_path = bundle_dir / "preflight.json"
    if preflight_path.is_file():
        try:
            preflight = json.loads(preflight_path.read_text())
        except json.JSONDecodeError:
            preflight = None
        if isinstance(preflight, dict):
            applies_verbatim = preflight.get("applies_verbatim")
    # Fail closed: only a literal True is the verbatim lane.
    return applies_verbatim is not True


def _cve_id_from_finding(bundle_dir: Path) -> str | None:
    finding_path = bundle_dir / "finding.json"
    if not finding_path.is_file():
        return None
    try:
        finding = json.loads(finding_path.read_text())
    except json.JSONDecodeError:
        return None
    if not isinstance(finding, dict):
        return None
    cve_id = finding.get("cve_id")
    return cve_id if isinstance(cve_id, str) and cve_id else None


class ReviewAdaptationEquivalenceScorer:
    """Compares the Reviewer's declared `equivalence:` verdict (adaptation
    lane, reviewer.v10+) against a registered ground-truth oracle
    (`agents/scorers/adaptation_oracle.py`).

    This is NOT part of `reviewer_scorer_names()` — see the note there. It
    only applies when ALL of the following hold:

      * the invocation produced a review (not a refusal)
      * the bundle is in the adaptation lane (source-context/ present +
        non-empty, preflight.json.applies_verbatim is not True)
      * finding.json exists, parses, and carries a cve_id
      * an oracle is registered for that cve_id

    Score:
      1.0 — reviewer's `equivalence:` token matches the oracle's
            ground_truth_equivalence exactly.
      0.0 — reviewer declared `indeterminate` against a settled oracle
            label (an under-commitment miss, distinct from a
            wrong-direction miss); OR the reviewer declared the opposite
            settled value or an unrecognized token (wrong-direction /
            unrecognized miss); OR review.md is missing/malformed; OR the
            adaptation-lane review has no `## Equivalence assessment`
            `equivalence:` line at all.
      None+applies=False — refusal, non-adaptation-lane bundle, no
            resolvable cve_id, or no registered oracle.
    """
    name = "review-adaptation-equivalence"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="reviewer refusal: adaptation-equivalence check is not applicable",
            )

        if not _is_adaptation_lane(bundle_dir):
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=(
                    "bundle is not in the adaptation lane (no non-empty "
                    "source-context/ or preflight.json.applies_verbatim is true)"
                ),
            )

        cve_id = _cve_id_from_finding(bundle_dir)
        if cve_id is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="finding.json missing, invalid, or lacks a cve_id",
            )

        oracle = get_oracle(cve_id)
        if oracle is None:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=f"no adaptation-equivalence oracle registered for {cve_id}",
            )

        # Bind the label to the SPECIFIC adjudicated adaptation. The oracle
        # verdict was settled against one canonical patch; a bundle carrying a
        # different patch (e.g. a re-run Patcher that produced a semantically
        # different, un-adjudicated adaptation) has no ground truth here. Abstain
        # (applies=False) rather than award the settled label to a patch nobody
        # adjudicated. Compare the on-disk patch.diff bytes — in a finalized
        # adaptation-lane bundle patch.diff IS the canonical, Builder-executed
        # artifact.
        patch_path = bundle_dir / "patch.diff"
        if not patch_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=f"patch.diff missing; cannot bind oracle label for {cve_id}",
            )
        bundle_patch_sha = sha256(patch_path.read_bytes()).hexdigest()
        if bundle_patch_sha != oracle.adjudicated_patch_sha256:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes=(
                    f"bundle patch.diff (sha256={bundle_patch_sha[:12]}…) does not "
                    f"match the adjudicated adaptation "
                    f"(sha256={oracle.adjudicated_patch_sha256[:12]}…) for {cve_id}; "
                    f"oracle label does not apply to this patch"
                ),
                details={
                    "cve_id": cve_id,
                    "bundle_patch_sha256": bundle_patch_sha,
                    "adjudicated_patch_sha256": oracle.adjudicated_patch_sha256,
                },
            )

        parsed = _load_review_md(bundle_dir)
        if parsed is None or parsed.kind != "review":
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="review.md missing or fails strict parser",
                details={
                    "cve_id": cve_id,
                    "reviewer_equivalence": None,
                    "ground_truth_equivalence": oracle.ground_truth_equivalence,
                    "oracle_base_relation": oracle.provenance.base_relation,
                    "oracle_adjudicated_by": oracle.adjudicated_by,
                    "match": False,
                },
            )

        reviewer_equivalence = parse_equivalence_verdict(parsed.equivalence_assessment_raw)

        details_base: dict[str, Any] = {
            "cve_id": cve_id,
            "reviewer_equivalence": reviewer_equivalence,
            "ground_truth_equivalence": oracle.ground_truth_equivalence,
            "oracle_base_relation": oracle.provenance.base_relation,
            "oracle_adjudicated_by": oracle.adjudicated_by,
            "adjudicated_patch_sha256": oracle.adjudicated_patch_sha256,
        }

        if reviewer_equivalence is None:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    "adaptation-lane review has no '## Equivalence assessment' "
                    "'equivalence:' line"
                ),
                details={**details_base, "match": False},
            )

        if reviewer_equivalence == oracle.ground_truth_equivalence:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=1.0,
                notes=(
                    f"reviewer equivalence={reviewer_equivalence!r} matches oracle "
                    f"ground truth for {cve_id}"
                ),
                details={**details_base, "match": True},
            )

        if reviewer_equivalence == "indeterminate":
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    f"reviewer declared 'indeterminate' against a settled oracle label "
                    f"({oracle.ground_truth_equivalence!r} for {cve_id}); "
                    f"under-commitment miss, not a wrong-direction miss"
                ),
                details={**details_base, "match": False},
            )

        if reviewer_equivalence not in VALID_EQUIVALENCE_VALUES:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    f"reviewer declared unrecognized equivalence value "
                    f"{reviewer_equivalence!r} (oracle ground truth is "
                    f"{oracle.ground_truth_equivalence!r} for {cve_id})"
                ),
                details={**details_base, "match": False},
            )

        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=0.0,
            notes=(
                f"reviewer equivalence={reviewer_equivalence!r} contradicts oracle "
                f"ground truth {oracle.ground_truth_equivalence!r} for {cve_id} "
                f"(wrong-direction miss)"
            ),
            details={**details_base, "match": False},
        )


# ─── 5. review-disagreement (advisory) ─────────────────────────────────────


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
    "ReviewAdaptationEquivalenceScorer",
    "ReviewCrossFamilyAttestationScorer",
    "ReviewDisagreementScorer",
    "ReviewEvidenceCitedScorer",
    "ReviewPatchComparisonPresentScorer",
    "ReviewSchemaValidScorer",
    "reviewer_scorer_names",
]
