"""Reproducer-specific scorers.

The Patcher's six scorers measure patch quality. The Reviewer's four
measure review quality. The Reproducer's scorers measure REPRODUCER
quality: did the model emit a well-formed reproducer, did the test
discriminate the unpatched vs patched paths in real Builder execution,
did the enumeration of `passthru.tests` match ground truth, and is
the chosen signal substring sufficiently CVE-specific?

v0 scorer set (locked in `docs/REPRODUCER_V1.md` §9):

  1. **repro-schema-valid** — non-advisory; pre-Builder. The model's
     output parses cleanly under the reproducer parser AND, if proxy,
     all four required `meta.proxy*` fields are present.

  2. **repro-unpatched-fails** — non-advisory; post-Builder; not
     applicable for proxy reproducers. Builder ran the test against
     the unpatched derivation; the SIGNAL_UNPATCHED substring appeared
     in stdout/stderr.

  3. **repro-patched-passes** — non-advisory; post-Builder. The
     SIGNAL_PATCHED substring appeared in the patched-path stdout/
     stderr. Applies even for proxy reproducers — proxies must still
     demonstrate their narrower patched-state evidence.

  4. **repro-passthru-recorded** — non-advisory; post-Builder. The
     model's `passthru-tests.json` enumeration matches the ground-truth
     set Builder discovers for the affected attr at `nixpkgs_rev`.
     Empty enumeration is valid only if the package truly has no such
     tests.

  5. **repro-signal-specificity** — advisory; post-Builder heuristic.
     Both signals are sufficiently CVE-specific: ≥ 32 chars, contains
     a CVE-summary keyword OR an upstream-fix-commit message symbol,
     not in the extended generic-token set.

The two load-bearing scorers (#2 and #3) consume `build.json` from
Builder. When `build.json` is not yet present (first-run, Builder not
wired), both record `applies=False` with a notes string explaining the
gate. The schema-valid + passthru-recorded scorers can fire pre-
Builder against the parser output alone.

Pre-Builder note: scorers 2/3/5 require Builder's execution-truth
record (`build.json`). Until Builder lands, they all record
applies=False with a structured notes message. This is the honest
v0 report — the same shape as Reviewer's `review-disagreement`
under partial signals.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agents.reproducer import (
    PROXY_REASON_ENUM,
    ReproducerOutputMalformed,
    ReproducerParseResult,
    parse_reproducer_output,
)
from agents.scorers.types import SCORER_VERSION, ScorerResult


def reproducer_scorer_names() -> tuple[str, ...]:
    """The locked Reproducer scorer names, in canonical order."""
    return (
        "repro-schema-valid",
        "repro-unpatched-fails",
        "repro-patched-passes",
        "repro-passthru-recorded",
        "repro-signal-specificity",
    )


# Extended generic-token set used by repro-signal-specificity (advisory).
# The parser already enforces a smaller floor list as a hard reject;
# this set widens it to catch padded-but-still-generic patterns.
_SPECIFICITY_GENERIC_PATTERNS: tuple[str, ...] = (
    "test failed",
    "test passed",
    "build failed",
    "build succeeded",
    "exit status non-zero",
    "exit status zero",
    "command failed",
    "process aborted",
    "assertion fired",
    "the patch is correct",
)


# Threshold for the advisory specificity scorer. The hard parser floor
# is 24; this raises the bar for "specific enough."
_SPECIFICITY_LENGTH_FLOOR = 32


# ─── shared helpers ────────────────────────────────────────────────────────


def _outputs_kind(invocation: dict[str, Any]) -> str:
    """Detect whether the reproducer invocation produced a reproducer or a refusal."""
    out_paths = {o["path"] for o in invocation.get("outputs") or []}
    if {"reproducer.nix", "reproducer-log.txt", "passthru-tests.json"}.issubset(
        out_paths
    ):
        return "reproducer"
    if "reproducer-refusal.json" in out_paths:
        return "refusal"
    return "unknown"


def _load_reproducer_output(bundle_dir: Path) -> ReproducerParseResult | None:
    """Read the three on-disk reproducer outputs and parse them.

    Returns None if any file is missing OR the combined output does
    not parse. The caller distinguishes "parsed" from "malformed" via
    the return value; missing-file is a structural fail at the scorer
    level (schema-valid → 0.0).
    """
    nix_p = bundle_dir / "reproducer.nix"
    log_p = bundle_dir / "reproducer-log.txt"
    json_p = bundle_dir / "passthru-tests.json"
    if not (nix_p.is_file() and log_p.is_file() and json_p.is_file()):
        return None
    raw = (
        "=== BEGIN reproducer.nix ===\n"
        + nix_p.read_text().rstrip("\n")
        + "\n=== END reproducer.nix ===\n"
        "=== BEGIN reproducer-log.txt ===\n"
        + log_p.read_text().rstrip("\n")
        + "\n=== END reproducer-log.txt ===\n"
        "=== BEGIN passthru-tests.json ===\n"
        + json_p.read_text().rstrip("\n")
        + "\n=== END passthru-tests.json ==="
    )
    try:
        return parse_reproducer_output(raw)
    except ReproducerOutputMalformed:
        return None


def _load_build_json(bundle_dir: Path) -> dict[str, Any] | None:
    """Read build.json (Builder's verdict record) if present."""
    p = bundle_dir / "build.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


# ─── 1. repro-schema-valid ────────────────────────────────────────────────


class ReproSchemaValidScorer:
    """Pre-Builder. Score 1.0 iff the parser accepts the on-disk output.

    For refusal invocations: scores against the parser's refusal rules
    (rule number in [1,8], one-line reason). 1.0 when the on-disk
    `reproducer-refusal.json` matches the parser-locked shape.
    """

    name = "repro-schema-valid"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        kind = _outputs_kind(invocation)
        if kind == "refusal":
            return self._score_refusal(bundle_dir)
        if kind == "reproducer":
            return self._score_reproducer(bundle_dir)
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=False,
            advisory=self.advisory,
            score=None,
            notes=(
                "no reproducer outputs and no reproducer-refusal.json found; "
                "scorer cannot apply"
            ),
        )

    def _score_reproducer(self, bundle_dir: Path) -> ScorerResult:
        parsed = _load_reproducer_output(bundle_dir)
        if parsed is None:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes=(
                    "reproducer outputs malformed or unparseable against the "
                    "v1 parser contract"
                ),
            )
        # Proxy claims must carry the four required meta fields. The
        # parser already validates this, but we surface it explicitly
        # in the scorer notes for cohort reporting.
        if parsed.is_proxy:
            assert parsed.proxy is not None
            details = {
                "is_proxy": True,
                "proxy_reason": parsed.proxy.proxy_reason,
            }
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=1.0,
                notes=(
                    f"reproducer parses cleanly; declared proxy with "
                    f"proxy_reason={parsed.proxy.proxy_reason!r} and the "
                    f"three required text fields"
                ),
                details=details,
            )
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=1.0,
            notes=(
                "reproducer parses cleanly; non-proxy; SIGNAL_UNPATCHED + "
                "SIGNAL_PATCHED satisfy length, generic-token, and distinct-"
                "signals rules; passthru-tests.json is well-shaped"
            ),
            details={"is_proxy": False},
        )

    def _score_refusal(self, bundle_dir: Path) -> ScorerResult:
        p = bundle_dir / "reproducer-refusal.json"
        if not p.is_file():
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes="reproducer-refusal.json missing on disk",
            )
        try:
            doc = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes=f"reproducer-refusal.json is not valid JSON: {exc}",
            )
        rule = doc.get("rule")
        reason = doc.get("reason")
        if not isinstance(rule, int) or not (1 <= rule <= 8):
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes=f"refusal rule {rule!r} is out of contract range [1, 8]",
            )
        if not isinstance(reason, str) or not reason.strip():
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes="refusal reason is empty or non-string",
            )
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=1.0,
            notes=f"refusal shape valid; rule={rule}",
            details={"refusal_rule": rule},
        )


# ─── 2. repro-unpatched-fails ─────────────────────────────────────────────


class ReproUnpatchedFailsScorer:
    """Post-Builder. Score 1.0 iff the SIGNAL_UNPATCHED substring
    appeared in the unpatched run's stdout/stderr per `build.json`.

    Not applicable for proxy reproducers (the proxy's `proxy_reason`
    explicitly says why unpatched-path evidence is out of scope).
    Not applicable when `build.json` is missing (Builder hasn't run).
    """

    name = "repro-unpatched-fails"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        if _outputs_kind(invocation) != "reproducer":
            return _na(
                self.name, self.advisory, "no reproducer outputs (refusal or unknown)"
            )
        parsed = _load_reproducer_output(bundle_dir)
        if parsed is None:
            return _na(
                self.name, self.advisory, "reproducer outputs missing or malformed"
            )
        build = _load_build_json(bundle_dir)
        if build is None:
            return _na(
                self.name,
                self.advisory,
                "build.json not present; Builder has not run yet — "
                "this scorer cannot apply pre-Builder",
            )
        if parsed.is_proxy:
            assert parsed.proxy is not None
            return _na(
                self.name,
                self.advisory,
                f"proxy reproducer (proxy_reason="
                f"{parsed.proxy.proxy_reason!r}); unpatched-path "
                "evidence is by design out of scope",
            )

        unpatched_run = _build_run(build, "unpatched")
        if unpatched_run is None:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes="build.json has no `unpatched` run record",
            )
        observed = unpatched_run.get("stdout_stderr") or ""
        assert parsed.log_unpatched is not None
        signal = parsed.log_unpatched.signal
        present = signal in observed
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=1.0 if present else 0.0,
            notes=(
                f"SIGNAL_UNPATCHED {'present' if present else 'NOT present'} "
                f"in build.json.unpatched.stdout_stderr"
            ),
            details={
                "signal_unpatched": signal,
                "signal_present": present,
                "exit_code": unpatched_run.get("exit_code"),
            },
        )


# ─── 3. repro-patched-passes ──────────────────────────────────────────────


class ReproPatchedPassesScorer:
    """Post-Builder. Score 1.0 iff the SIGNAL_PATCHED substring
    appeared in the patched run's stdout/stderr per `build.json`.

    Applies even for proxy reproducers — proxies must still demonstrate
    their narrower patched-state evidence.
    """

    name = "repro-patched-passes"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        if _outputs_kind(invocation) != "reproducer":
            return _na(
                self.name, self.advisory, "no reproducer outputs (refusal or unknown)"
            )
        parsed = _load_reproducer_output(bundle_dir)
        if parsed is None:
            return _na(
                self.name, self.advisory, "reproducer outputs missing or malformed"
            )
        build = _load_build_json(bundle_dir)
        if build is None:
            return _na(
                self.name,
                self.advisory,
                "build.json not present; Builder has not run yet — "
                "this scorer cannot apply pre-Builder",
            )

        patched_run = _build_run(build, "patched")
        if patched_run is None:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes="build.json has no `patched` run record",
            )
        observed = patched_run.get("stdout_stderr") or ""
        assert parsed.log_patched is not None
        signal = parsed.log_patched.signal
        present = signal in observed
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=1.0 if present else 0.0,
            notes=(
                f"SIGNAL_PATCHED {'present' if present else 'NOT present'} "
                f"in build.json.patched.stdout_stderr"
            ),
            details={
                "signal_patched": signal,
                "signal_present": present,
                "exit_code": patched_run.get("exit_code"),
                "is_proxy": parsed.is_proxy,
            },
        )


# ─── 4. repro-passthru-recorded ───────────────────────────────────────────


class ReproPassthruRecordedScorer:
    """Post-Builder. Score = (model-enumerated ∩ ground-truth) / ground-truth.

    Builder enumerates the actual `passthru.tests` and `nixosTests`
    attrs for the affected attr at `nixpkgs_rev`; the model enumerated
    them in `passthru-tests.json`. The scorer compares names. Empty-on-
    both-sides is valid (score 1.0 by convention). Missing build.json:
    not applicable.
    """

    name = "repro-passthru-recorded"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        if _outputs_kind(invocation) != "reproducer":
            return _na(
                self.name, self.advisory, "no reproducer outputs (refusal or unknown)"
            )
        parsed = _load_reproducer_output(bundle_dir)
        if parsed is None:
            return _na(
                self.name, self.advisory, "reproducer outputs missing or malformed"
            )
        build = _load_build_json(bundle_dir)
        if build is None:
            return _na(
                self.name,
                self.advisory,
                "build.json not present; Builder has not run yet — "
                "this scorer cannot apply pre-Builder",
            )
        ground_truth = build.get("passthru_tests_ground_truth")
        if not isinstance(ground_truth, list):
            return _na(
                self.name,
                self.advisory,
                "build.json.passthru_tests_ground_truth absent or not a list",
            )
        gt_names = {
            entry.get("name") for entry in ground_truth if isinstance(entry, dict)
        }
        gt_names.discard(None)
        model_names = {e.name for e in parsed.passthru_tests}
        if not gt_names and not model_names:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=1.0,
                notes="no passthru tests defined for affected attr; empty enumeration is correct",
                details={"ground_truth_count": 0, "model_count": 0},
            )
        if not gt_names:
            return ScorerResult(
                scorer_name=self.name,
                scorer_version=self.version,
                applies=True,
                advisory=self.advisory,
                score=0.0,
                notes=(
                    "model enumerated passthru tests but Builder found none; "
                    "the model invented entries"
                ),
                details={
                    "ground_truth_count": 0,
                    "model_count": len(model_names),
                    "spurious": sorted(model_names),
                },
            )
        intersection = gt_names & model_names
        recall = len(intersection) / len(gt_names)
        missing = sorted(gt_names - model_names)
        spurious = sorted(model_names - gt_names)
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=recall,
            notes=(
                f"{len(intersection)}/{len(gt_names)} ground-truth passthru "
                f"tests recorded by model"
                + (f"; missing: {missing}" if missing else "")
                + (f"; spurious: {spurious}" if spurious else "")
            ),
            details={
                "ground_truth_count": len(gt_names),
                "model_count": len(model_names),
                "intersection_count": len(intersection),
                "missing": missing,
                "spurious": spurious,
            },
        )


# ─── 5. repro-signal-specificity (advisory) ──────────────────────────────


class ReproSignalSpecificityScorer:
    """Advisory. Heuristic for "the named signal is sufficiently CVE-specific."

    Stack:
      * each signal length ≥ _SPECIFICITY_LENGTH_FLOOR (32)
      * neither signal matches an extended generic-token pattern
        (`test failed`, `build failed`, `command failed`, ...)
      * at least one signal contains a word ≥ 5 chars from the CVE
        summary OR a function/symbol name from any
        `upstream_fix_commits[].message` (using a coarse word-boundary
        match)

    Score: fraction of axes satisfied (3 axes → 0.0 / 0.33 / 0.67 / 1.0).
    Advisory because heuristic; not gating.
    """

    name = "repro-signal-specificity"
    version = SCORER_VERSION
    advisory = True

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        if _outputs_kind(invocation) != "reproducer":
            return _na(
                self.name, self.advisory, "no reproducer outputs (refusal or unknown)"
            )
        parsed = _load_reproducer_output(bundle_dir)
        if parsed is None:
            return _na(
                self.name, self.advisory, "reproducer outputs missing or malformed"
            )
        build = _load_build_json(bundle_dir)
        if build is None:
            return _na(
                self.name,
                self.advisory,
                "build.json not present; Builder has not run yet — "
                "this advisory scorer is reported only post-Builder",
            )

        finding = _read_json(bundle_dir / "finding.json") or {}
        upstream_ref = _read_json(bundle_dir / "upstream-ref.json") or {}

        assert parsed.log_unpatched is not None
        assert parsed.log_patched is not None
        sig_u = parsed.log_unpatched.signal
        sig_p = parsed.log_patched.signal

        axis_length = (
            len(sig_u) >= _SPECIFICITY_LENGTH_FLOOR
            and len(sig_p) >= _SPECIFICITY_LENGTH_FLOOR
        )
        axis_not_generic = not _matches_extended_generic(
            sig_u
        ) and not _matches_extended_generic(sig_p)
        keywords = _cve_keywords(finding, upstream_ref)
        axis_keyword = _signal_contains_any_keyword(
            sig_u, keywords
        ) or _signal_contains_any_keyword(sig_p, keywords)
        score = (int(axis_length) + int(axis_not_generic) + int(axis_keyword)) / 3
        return ScorerResult(
            scorer_name=self.name,
            scorer_version=self.version,
            applies=True,
            advisory=self.advisory,
            score=round(score, 3),
            notes=(
                f"specificity axes — "
                f"length≥{_SPECIFICITY_LENGTH_FLOOR}: {axis_length}; "
                f"not extended-generic: {axis_not_generic}; "
                f"contains CVE-keyword: {axis_keyword}"
            ),
            details={
                "axis_length": axis_length,
                "axis_not_generic": axis_not_generic,
                "axis_keyword_match": axis_keyword,
                "keywords_considered": sorted(keywords)[:20],
            },
        )


# ─── helpers ──────────────────────────────────────────────────────────────


def _na(name: str, advisory: bool, notes: str) -> ScorerResult:
    return ScorerResult(
        scorer_name=name,
        scorer_version=SCORER_VERSION,
        applies=False,
        advisory=advisory,
        score=None,
        notes=notes,
    )


def _build_run(build: dict[str, Any], which: str) -> dict[str, Any] | None:
    """Pull the `unpatched` or `patched` run record from build.json.

    The expected shape is:
        build = {
            "unpatched": {"exit_code": 1, "stdout_stderr": "..."},
            "patched":   {"exit_code": 0, "stdout_stderr": "..."},
            ...
        }
    Other keys are tolerated. The scorer is permissive on schema since
    Builder's exact build.json shape is the next milestone; what's
    required here is `<which>.stdout_stderr` (string) and
    `<which>.exit_code` (int).
    """
    rec = build.get(which)
    if not isinstance(rec, dict):
        return None
    return rec


def _read_json(p: Path) -> dict[str, Any] | None:
    if not p.is_file():
        return None
    try:
        v = json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
    return v if isinstance(v, dict) else None


_GENERIC_PATTERN_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(re.escape(p), re.IGNORECASE) for p in _SPECIFICITY_GENERIC_PATTERNS
)


def _matches_extended_generic(signal: str) -> bool:
    """True iff the signal contains any extended generic pattern."""
    for r in _GENERIC_PATTERN_RES:
        if r.search(signal):
            return True
    return False


def _cve_keywords(finding: dict, upstream_ref: dict) -> set[str]:
    """Build a coarse keyword set from finding.summary + upstream_fix_commits[].message.

    Keywords are alphanumeric tokens of length ≥ 5. Lower-cased. Used
    by the specificity heuristic to check that the signal contains at
    least one CVE-class anchor word.
    """
    keywords: set[str] = set()
    for source_text in _extract_keyword_sources(finding, upstream_ref):
        for tok in re.findall(r"[A-Za-z0-9_]+", source_text):
            if len(tok) >= 5:
                keywords.add(tok.lower())
    return keywords


def _extract_keyword_sources(
    finding: dict,
    upstream_ref: dict,
) -> list[str]:
    sources: list[str] = []
    summary = finding.get("summary")
    if isinstance(summary, str):
        sources.append(summary)
    for fc in upstream_ref.get("upstream_fix_commits") or []:
        if isinstance(fc, dict):
            msg = fc.get("message")
            if isinstance(msg, str):
                sources.append(msg)
    return sources


def _signal_contains_any_keyword(signal: str, keywords: set[str]) -> bool:
    if not keywords:
        return False
    lower = signal.lower()
    for kw in keywords:
        if kw in lower:
            return True
    return False


__all__ = [
    "PROXY_REASON_ENUM",
    "ReproPassthruRecordedScorer",
    "ReproPatchedPassesScorer",
    "ReproSchemaValidScorer",
    "ReproSignalSpecificityScorer",
    "ReproUnpatchedFailsScorer",
    "reproducer_scorer_names",
]
