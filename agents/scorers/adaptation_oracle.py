"""Adaptation-equivalence oracle registry.

The Reviewer's adaptation lane (reviewer.v10) judges whether a model-authored
backport is *semantically equivalent* to the upstream fix once adapted to the
pinned base. To evaluate whether that verdict is CORRECT we need a ground-truth
label per bundle — the answer a human adjudicator reached by comparing the
authored adaptation against a trusted human backport (the "oracle").

**Isolation property (load-bearing).** The oracle patch is *referenced, not
vendored*. It must never enter Patcher or Reviewer context: a model that could
read the human backport would be transcribing an answer key, not authoring or
judging an adaptation. So this registry stores only:

  * the human-adjudicated ground-truth equivalence label, and
  * the oracle's PROVENANCE (where the human backport lives + its sha256),

never the oracle patch bytes. An auditor re-fetches the oracle from its recorded
provenance to re-verify the label; nothing in a bundle directory carries it.

The registry is keyed by CVE id (finding.json.cve_id). The eval-time consumer is
`ReviewAdaptationEquivalenceScorer` in reviewer_scorers.py, which compares a
Reviewer's declared `equivalence:` verdict against `ground_truth_equivalence`
here. A CVE with no entry is simply un-scored (applies=False) — the harness never
guesses a label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_sha256_hex(s: str) -> bool:
    return isinstance(s, str) and bool(_SHA256_HEX_RE.match(s))


# Ground-truth labels an adjudicator may record. Mirrors the Reviewer's
# `equivalence:` value space (agents.reviewer.parser.VALID_EQUIVALENCE_VALUES),
# minus `indeterminate`: an oracle label is a settled human judgment, so the
# ground truth is always equivalent or not-equivalent. (A Reviewer verdict of
# `indeterminate` is scored as a miss against either settled label — see the
# scorer.)
VALID_ORACLE_LABELS: frozenset[str] = frozenset({"equivalent", "not-equivalent"})


@dataclass(frozen=True)
class OracleProvenance:
    """Where the trusted human backport lives, so the label is auditable.

    `source` is a human-readable origin (e.g. "nixpkgs"). `ref` pins the
    revision. `path` locates the patch within that ref. `sha256` is the hex
    digest of the oracle patch bytes at that location — an auditor fetches the
    patch and checks the digest before trusting the label. `base_relation`
    records how the oracle's base relates to trace's pinned base:
    `same-base` (strongest — the human backport targets the identical pinned
    version) or `near-base` (a neighbouring version; the adjudication accounts
    for the base delta).
    """

    source: str
    ref: str
    path: str
    sha256: str
    base_relation: str  # "same-base" | "near-base"

    def __post_init__(self) -> None:
        # The digest is the documented integrity check an auditor uses when
        # re-fetching the trusted human patch; a malformed value makes the
        # entry unauditable, so reject it at construction.
        if not _is_sha256_hex(self.sha256):
            raise ValueError(
                f"provenance.sha256 must be 64 hex chars; got {self.sha256!r}"
            )
        if self.base_relation not in {"same-base", "near-base"}:
            raise ValueError(
                f"base_relation must be 'same-base' or 'near-base'; got "
                f"{self.base_relation!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ref": self.ref,
            "path": self.path,
            "sha256": self.sha256,
            "base_relation": self.base_relation,
        }


@dataclass(frozen=True)
class AdaptationOracle:
    """A ground-truth entry for adaptation-equivalence scoring.

    An oracle label is adjudicated against ONE specific model-authored
    adaptation. It does not generalize to any future adaptation for the same
    CVE: a re-run Patcher may emit a semantically different patch that a human
    never adjudicated. So the entry pins `adjudicated_patch_sha256` — the
    sha256 of the canonical (Builder-executed) patch.diff that was adjudicated
    — and the scorer applies this label ONLY to a bundle whose patch.diff hash
    matches. A bundle carrying a different adaptation is left unscored
    (applies=False), never awarded the settled label.
    """

    cve_id: str
    ground_truth_equivalence: str  # one of VALID_ORACLE_LABELS
    # sha256 of the canonical patch.diff bytes that were adjudicated. Binds the
    # label to the specific adaptation; the scorer requires an exact match.
    adjudicated_patch_sha256: str
    provenance: OracleProvenance
    adjudicated_by: str  # who/what settled the label (audit trail)
    notes: str = ""
    # Deltas the adjudicator judged non-semantic (so a Reviewer that flags one
    # as a difference is over-strict, not wrong-verdict). Informational.
    accepted_deltas: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.ground_truth_equivalence not in VALID_ORACLE_LABELS:
            raise ValueError(
                f"ground_truth_equivalence must be one of "
                f"{sorted(VALID_ORACLE_LABELS)}; got "
                f"{self.ground_truth_equivalence!r}"
            )
        # provenance.base_relation and provenance.sha256 are validated by
        # OracleProvenance.__post_init__.
        if not _is_sha256_hex(self.adjudicated_patch_sha256):
            raise ValueError(
                f"adjudicated_patch_sha256 must be 64 hex chars; got "
                f"{self.adjudicated_patch_sha256!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "ground_truth_equivalence": self.ground_truth_equivalence,
            "adjudicated_patch_sha256": self.adjudicated_patch_sha256,
            "provenance": self.provenance.to_dict(),
            "adjudicated_by": self.adjudicated_by,
            "notes": self.notes,
            "accepted_deltas": list(self.accepted_deltas),
        }


# ─── the registry ──────────────────────────────────────────────────────────
#
# One entry per adaptation-lane bundle whose equivalence has been settled
# against a trusted human backport. Keep this list append-only in spirit; when
# an oracle's provenance changes (e.g. nixpkgs rev bump) add a new entry note
# rather than silently rewriting a settled label.

_REGISTRY: dict[str, AdaptationOracle] = {}


def _register(oracle: AdaptationOracle) -> None:
    if oracle.cve_id in _REGISTRY:
        raise ValueError(f"duplicate oracle registration for {oracle.cve_id}")
    _REGISTRY[oracle.cve_id] = oracle


# maxima CVE-2024-34490 — predictable plot tempfile names (CWE-377). Upstream
# fix 51704cc generates the output filename with `random-name` across
# src/gnuplot_def.lisp, src/plot.lisp, src/xmaxima_def.lisp. The fix is an
# untagged source commit; the pinned base is 5.47.0, so upstream-fix.patch does
# NOT apply verbatim (6/8 hunks fail on context drift) and the Patcher authored
# an adaptation. nixpkgs carries a same-base human backport of the identical
# fix, adjudicated to be equivalent to the model's adaptation at all five
# random-name insertion sites; the only delta is a Common Lisp format-directive
# case-fold (`~(~a~)` vs `~a`) which does not change the generated filename.
_register(
    AdaptationOracle(
        cve_id="CVE-2024-34490",
        ground_truth_equivalence="equivalent",
        # sha256 of the canonical (Builder-executed) patch.diff that was
        # adjudicated. Re-derivable: canonicalize_backport_patch() over the
        # maxima draft's raw patch.diff + source-context yields this digest.
        adjudicated_patch_sha256=(
            "21acad11adabdf29ea2585b424e6ebb4bbcdccfa41d8ae2fb9b6b21c03ed9bed"
        ),
        provenance=OracleProvenance(
            source="nixpkgs",
            ref="08215d1b",
            path="pkgs/applications/science/math/maxima/5.47.0-CVE-2024-34490.patch",
            # sha256 of the oracle patch bytes at that ref/path; an auditor
            # re-fetches (raw.githubusercontent.com/NixOS/nixpkgs/<ref>/<path>)
            # and verifies this digest before trusting the label.
            sha256="a5da1348cf3d0837f58ea10e1377b9bb0740624c6ae13a5befe0da4337bc8880",
            base_relation="same-base",
        ),
        adjudicated_by="trace-maintainer-handcheck-2026-07-27",
        notes=(
            "Adaptation matches the same-base nixpkgs human backport at all 5 "
            "random-name sites; sole delta is a ~(~a~) case-fold format directive "
            "that does not change the emitted filename."
        ),
        accepted_deltas=(
            "format directive case-fold ~(~a~) vs ~a (identical output filename)",
        ),
    )
)


# ─── lookup API ────────────────────────────────────────────────────────────


def get_oracle(cve_id: str) -> AdaptationOracle | None:
    """Return the registered oracle for a CVE id, or None when unregistered."""
    return _REGISTRY.get(cve_id)


def registered_cve_ids() -> tuple[str, ...]:
    """CVE ids with a registered adaptation-equivalence oracle, sorted."""
    return tuple(sorted(_REGISTRY))


__all__ = [
    "AdaptationOracle",
    "OracleProvenance",
    "VALID_ORACLE_LABELS",
    "get_oracle",
    "registered_cve_ids",
]
