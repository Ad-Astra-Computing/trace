"""Source-backport behavioral validation gate.

A *source-backport* (the Patcher AUTHORS an in-tree code fix instead of bumping the
package version) only counts toward the training corpus if it is *behaviorally
validated*: the cert must have built BOTH the vulnerable baseline and the
agent-backported tree at the SAME package version, run the discriminating
reproducer against each, and observed the vulnerability FIRE on the baseline but
NOT on the backport. Reviewer semantic-match against `upstream-fix.patch` ground
truth is necessary but NOT sufficient (codex peer 2026-06-15): a patch that
matches the upstream fix in shape can still fail to build or fail to suppress the
bug. This module turns "the backport actually fixes the CVE" into a
machine-checkable verdict read from the cert's `build.json`.

It deliberately does NOT route through `agents.scorers.reproducer_scorers`: those
gate on the Reproducer *agent*'s output sidecars (`reproducer-log.txt`,
`passthru-tests.json`), which source-backport bundles do not carry — their
`reproducer.nix` is hand-authored (often ASAN-instrumented). The behavioral
evidence that matters is what the Builder OBSERVED, recorded in
`build.json.{unpatched,patched}.stdout_stderr`, regardless of who authored the
reproducer.

Codex-confirmed assertion set (every load-bearing assertion must pass for
`validated`):

  1. patch-applies               build.json.patch_apply.applied is True
  2. unpatched-reproducer-fires  SIGNAL_UNPATCHED observed on the pre-patch tree
  3. backported-reproducer-clean SIGNAL_PATCHED observed on the agent-patched tree
  4. no-version-bump             patch.diff changes source, not version=/hash=
  5. semantic-match-upstream-fix upstream-fix.patch present + Reviewer accept
  6. no-proxy-signal             a real unpatched discriminator, not a proxy

`validated` source-backports are the valuable training data (the agent authored a
real code fix, proven to address the CVE). Source-backports that fail any
load-bearing assertion are `verified-only` (built + Reviewer-accepted but not
behaviorally proven) and do NOT count toward the source-backport corpus target —
the common recoverable case is a `patched-build-timed-out` cert that needs a
longer `builder_timeout_seconds` re-run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Lines an added-to-package.nix hunk must NOT introduce: a source-backport that
# silently bumped the version or a fetcher hash is no longer a source-backport.
_VERSION_BUMP_RE = re.compile(
    r"""^\+(?!\+\+)              # an added line (not the +++ file header)
        .*\b(
            version\s*=\s*["']   # version = "x.y.z"
          | rev\s*=\s*["']       # rev = "..."
          | (sha256|sha512|hash|cargoHash|vendorHash|npmDepsHash|outputHash)\s*=
        )""",
    re.VERBOSE,
)


@dataclass(frozen=True)
class Assertion:
    """One validation check. `load_bearing` assertions must all pass for the
    bundle to be `validated`; advisory ones are reported but never block."""

    name: str
    passed: bool
    load_bearing: bool
    detail: str


@dataclass(frozen=True)
class BackportValidation:
    bundle: str
    is_source_backport: bool
    validated: bool
    disposition: str  # "validated" | "verified-only" | "not-source-backport"
    assertions: list[Assertion] = field(default_factory=list)

    def failed_load_bearing(self) -> list[str]:
        return [a.name for a in self.assertions if a.load_bearing and not a.passed]

    def to_dict(self) -> dict:
        return {
            "bundle": self.bundle,
            "is_source_backport": self.is_source_backport,
            "validated": self.validated,
            "disposition": self.disposition,
            "failed_load_bearing": self.failed_load_bearing(),
            "assertions": [
                {
                    "name": a.name,
                    "passed": a.passed,
                    "load_bearing": a.load_bearing,
                    "detail": a.detail,
                }
                for a in self.assertions
            ],
        }


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def is_source_backport(bundle_dir: Path) -> bool:
    """True iff the bundle is resolver-authorized as a source-backport. The
    authoritative signal is `upstream-ref.json.eligibility.patch_strategy ==
    "source-backport"`; that field is what gates the Patcher's source-backport
    behavior in the first place (agents/patcher/runner.py)."""
    u = _read_json(bundle_dir / "upstream-ref.json") or {}
    if (u.get("eligibility") or {}).get("patch_strategy") == "source-backport":
        return True
    b = _read_json(bundle_dir / "bundle.json") or {}
    return b.get("patch_strategy") == "source-backport"


def _reviewer_accepted(bundle_dir: Path) -> bool:
    review = bundle_dir / "review.md"
    if not review.is_file():
        return False
    head = review.read_text()[:400].lower()
    if "## verdict" not in head:
        return False
    return "accept" in head.split("## verdict", 1)[1][:40]


def _no_version_bump(bundle_dir: Path) -> tuple[bool, str]:
    """A source-backport must change source, not the version/hash. Fails if any
    added line looks like a version/rev/hash assignment; also requires positive
    evidence of a source change (a new `.patch` file added, or a non-.nix file
    touched) so an empty/degenerate diff cannot pass by absence."""
    patch = bundle_dir / "patch.diff"
    if not patch.is_file():
        return False, "patch.diff missing"
    text = patch.read_text()
    offenders = [
        ln for ln in text.splitlines() if _VERSION_BUMP_RE.match(ln)
    ]
    if offenders:
        return False, f"version/hash change in patch.diff: {offenders[0].strip()[:60]!r}"

    # Positive source-change evidence: prefer the Builder's own record of which
    # files the patch touched; fall back to parsing the diff headers.
    build = _read_json(bundle_dir / "build.json") or {}
    changed = (build.get("patch_apply") or {}).get("files_changed") or []
    if not changed:
        changed = re.findall(r"^\+\+\+ b/(.+)$", text, re.MULTILINE)
    adds_patch_file = any(str(f).endswith(".patch") for f in changed)
    touches_source = any(not str(f).endswith(".nix") for f in changed)
    if adds_patch_file or touches_source:
        ev = next((f for f in changed if str(f).endswith(".patch")), None) or \
             next((f for f in changed if not str(f).endswith(".nix")), "source")
        return True, f"source change, no version/hash bump (e.g. {ev})"
    return False, f"no source-file change found in patch (files={changed})"


def _signal_in_run(build: dict, run: str, marker: str) -> tuple[bool, str]:
    rec = build.get(run) or {}
    outcome = rec.get("outcome")
    observed = rec.get("stdout_stderr") or ""
    if outcome == "timed-out":
        return False, f"{run} run timed-out (re-cert with longer builder_timeout_seconds)"
    if outcome not in ("succeeded", None) and marker not in observed:
        return False, f"{run} run outcome={outcome!r}, {marker} not observed"
    present = marker in observed
    return present, (
        f"{marker} {'observed' if present else 'NOT observed'} in build.json.{run}"
    )


def validate_backport(bundle_dir: Path) -> BackportValidation:
    """Compute the behavioral-validation verdict for one bundle."""
    name = bundle_dir.name
    if not is_source_backport(bundle_dir):
        return BackportValidation(
            bundle=name, is_source_backport=False, validated=False,
            disposition="not-source-backport",
        )

    build = _read_json(bundle_dir / "build.json") or {}
    repro_text = ""
    rp = bundle_dir / "reproducer.nix"
    if rp.is_file():
        repro_text = rp.read_text()

    checks: list[Assertion] = []

    applied = (build.get("patch_apply") or {}).get("applied") is True
    checks.append(Assertion(
        "patch-applies", applied, True,
        "build.json.patch_apply.applied" if applied
        else "patch did not apply (or no build.json — cert has not run)",
    ))

    fires, fdetail = _signal_in_run(build, "unpatched", "SIGNAL_UNPATCHED")
    checks.append(Assertion("unpatched-reproducer-fires", fires, True, fdetail))

    clean, cdetail = _signal_in_run(build, "patched", "SIGNAL_PATCHED")
    checks.append(Assertion("backported-reproducer-clean", clean, True, cdetail))

    no_bump, bdetail = _no_version_bump(bundle_dir)
    checks.append(Assertion("no-version-bump", no_bump, True, bdetail))

    has_gt = (bundle_dir / "upstream-fix.patch").is_file()
    accepted = _reviewer_accepted(bundle_dir)
    sem = has_gt and accepted
    checks.append(Assertion(
        "semantic-match-upstream-fix", sem, True,
        "upstream-fix.patch present + Reviewer accept" if sem else
        f"ground-truth={'present' if has_gt else 'MISSING'}, "
        f"reviewer-accept={'yes' if accepted else 'no'}",
    ))

    # no-proxy-signal: a genuine discriminator defines BOTH a distinct
    # unpatched and patched signal in the reproducer; a proxy emits only the
    # patched/fallback signal. Combined with unpatched-reproducer-fires above,
    # this excludes the "fallback fires the signal" failure mode.
    has_both = "SIGNAL_UNPATCHED" in repro_text and "SIGNAL_PATCHED" in repro_text
    checks.append(Assertion(
        "no-proxy-signal", has_both, True,
        "reproducer defines distinct unpatched + patched signals" if has_both
        else "reproducer.nix lacks a distinct unpatched discriminator (proxy-shaped)",
    ))

    validated = all(a.passed for a in checks if a.load_bearing)
    return BackportValidation(
        bundle=name,
        is_source_backport=True,
        validated=validated,
        disposition="validated" if validated else "verified-only",
        assertions=checks,
    )


def scan_source_backports(corpus_root: Path) -> list[BackportValidation]:
    """Validate every source-backport bundle under `corpus_root` (e.g.
    traces/example). Returns one result per source-backport, sorted by name."""
    out: list[BackportValidation] = []
    for bd in sorted(corpus_root.glob("CVE-*")):
        if not bd.is_dir() or bd.name.startswith("CVE-0000-"):
            continue
        if is_source_backport(bd):
            out.append(validate_backport(bd))
    return out
