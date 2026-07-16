"""Deterministic metadata-consistency lint for proposed patch bundles.

This is a *contract-layer* check, not a model check. The Reviewer model reasons
about code hunks; it is a poor and unnecessary tool for verifying that a version
string, a source hash and a rationale all agree. Those are mechanical field
comparisons against the resolver's trusted output (`upstream-ref.json`, produced
by the deterministic UpstreamRefResolver — no model), so the contract layer can
settle them with certainty and zero false-reject risk on honest patches.

Empirically (fresh 34-fold reviewer eval, 2026-07-14) three of the Reviewer-LoRA's
seven false-accepts were metadata mutations the model never examined. Two of them
are settled here deterministically, grounded in the resolver target:

  * ``version-without-hash``  — version bumped, ``src.hash`` left unchanged
  * ``wrong-src-hash``        — new hash does not match the prefetched source

(The third, ``rationale-cites-wrong-version``, is deliberately *not* linted: the
only signal is free-form rationale prose, and a source-backport legitimately cites
the upstream fix version while pinning the old nixpkgs version, so a
rationale-vs-target check false-rejects honest backports. A merge gate must never
false-reject an honest patch, so that case stays with the model.)

The lint also catches the broader ``version-mismatch-vs-resolver`` family (a diff
that bumps to a version the resolver did not target). It is meant to run as a gate
*beside* the Reviewer (model or LoRA): a metadata violation is a reject regardless
of what the model concludes about the code, keeping the trust boundary in the
contract layer where trace puts it.

The source-hash check is framed to avoid the irreducible ambiguity of the nixpkgs
``hash`` attribute (a bare ``hash = "..."`` may be the source tarball OR a
``fetchpatch``/sub-fetcher, indistinguishable by regex). Rather than classify a
diff hash, the lint checks for the *presence* of the resolver's known-correct
source hash among the diff's added hash lines: on a version bump the prefetched
source hash must appear, so its absence means the source hash was left stale
(``version-without-hash``) or changed to a wrong value (``wrong-src-hash``). This
is sound in both directions — an honest bump always adds the prefetched hash, and
a source-backport (no version change) is skipped entirely. Vendor/cargo and
sub-fetcher hashes are deliberately out of scope here (they are verified at build
time); the gate targets the source tarball hash, which is what the corpus
metadata mutations attack.

The lint is deliberately conservative: it only fires when it can ground a
disagreement in resolver-provided output, and every check is verified to produce
zero findings on the honest-positive corpus. A source-backport that adds a
``.patch`` file (no version change) produces no findings, so honest patches —
version-bump or source-backport — pass clean.

Known limitation (deliberate). The nixpkgs ``hash`` attribute is irreducibly
ambiguous under regex: a bare ``hash = "..."`` may be the source tarball OR a
``fetchpatch``/sub-fetcher, indistinguishable without a fetcher-block-aware nix
parser. This gate is tuned so that ambiguity always fails SAFE — it never
false-rejects an honest patch (the cardinal property for a merge gate, verified
across the whole positive corpus). The cost is a narrow class of contrived
multi-``hash`` shapes it can miss (e.g. a wrong ``src.hash`` while the resolver's
source value coincidentally appears on a sub-fetcher ``hash`` line). Those defects
are not silently accepted end-to-end: they fall through to the Reviewer and the
build, exactly as they did before this gate existed. Structural fetcher-block
parsing to close the residual is out of scope; it would add a new false-reject
surface to catch shapes absent from the corpus, the wrong trade for a gate whose
job is to remove false-accepts without ever blocking honest work.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class MetadataViolation:
    """One deterministic metadata-consistency defect."""

    code: str
    message: str
    evidence: dict = field(default_factory=dict)


# `+  version = "1.2.3";`  /  `-  version = "1.2.3";`
_VERSION_RE = re.compile(r'^([+-])\s*version\s*=\s*"([^"]+)"\s*;', re.M)
# Any hash-family attribute assignment on an added/removed diff line — used only to
# detect whether *some* hash was touched (version-without-hash vs wrong-src-hash).
_HASH_RE = re.compile(
    r'^([+-])\s*(?:hash|sha256|sha512|vendorHash|vendorSha256|cargoHash|'
    r'cargoSha256|outputHash|npmDepsHash)\s*=\s*"([^"]+)"',
    re.M,
)
# Source-tarball hash candidates only (``hash`` / ``sha256`` / ``sha512``). The
# resolver's source hash is looked for ONLY on these lines, so a src value that
# lands on a ``vendorHash``/``cargoHash`` line does not satisfy the source check
# (a bare ``hash`` may be the src OR a sub-fetcher, but never vendor/cargo — those
# have their own attribute names).
_SRC_HASH_RE = re.compile(r'^([+-])\s*(?:hash|sha256|sha512)\s*=\s*"([^"]+)"', re.M)

# Resolver prefetch names that denote the primary source tarball hash.
_SRC_HASH_NAMES = {"src.hash", "src.sha256", "src.sha512"}


def _nix_hunk_text(diff: str) -> str:
    """Return only the hunk content of ``*.nix`` files in a unified diff.

    A source-backport adds a ``.patch`` file whose payload can contain lines like
    ``+ version = "...";`` — that is embedded patch content, NOT a change to the
    package expression, and must not be read as a version/hash edit (doing so
    false-rejects honest backports). This keeps only ``+``/``-``/context lines that
    belong to a ``.nix`` file's hunks, so version/hash matching never sees patch
    payload or non-nix files."""
    out: list[str] = []
    is_nix = False
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            is_nix = False  # reset until the target header names the file
            continue
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            if path.startswith("b/"):
                path = path[2:]
            is_nix = path.endswith(".nix")
            continue
        if line.startswith(("--- ", "@@", "index ")):
            continue
        if is_nix and line[:1] in ("+", "-", " "):
            out.append(line)
    return "\n".join(out)


def _version_side_values(text: str) -> tuple[list[str], list[str]]:
    removed, added = [], []
    for m in _VERSION_RE.finditer(text):
        (added if m.group(1) == "+" else removed).append(m.group(2))
    return removed, added


def _diff_new_version(diff: str) -> tuple[str | None, str | None]:
    """Return (old_version, new_version) if the diff changes ``version``."""
    removed, added = _version_side_values(diff)
    old = removed[0] if removed else None
    new = added[0] if added else None
    return old, new


def _diff_added_src_hash_values(diff: str) -> set[str]:
    """Values on ``+`` lines of source-hash attributes (hash/sha256/sha512) only."""
    return {m.group(2) for m in _SRC_HASH_RE.finditer(diff) if m.group(1) == "+"}


def _diff_has_hash_change(diff: str) -> bool:
    """True iff some added hash value is not also a removed value (a real change)."""
    added = {m.group(2) for m in _HASH_RE.finditer(diff) if m.group(1) == "+"}
    removed = {m.group(2) for m in _HASH_RE.finditer(diff) if m.group(1) == "-"}
    return bool(added - removed)


def _resolver_target_version(upstream_ref: dict) -> str | None:
    v = upstream_ref.get("target_version")
    return str(v) if v else None


def _resolver_src_hash(upstream_ref: dict) -> str | None:
    """The resolver's known-correct source tarball hash, if grounded."""
    for h in upstream_ref.get("prefetch_hashes", []) or []:
        if h.get("name") in _SRC_HASH_NAMES:
            return h.get("value") or h.get("hash")
    return None


def check_metadata_consistency(bundle_dir: str | Path) -> list[MetadataViolation]:
    """Deterministically lint a bundle's version/hash/rationale metadata.

    Grounds every finding in ``upstream-ref.json`` (trusted resolver output).
    Returns an empty list for honest patches (including source-backports that
    change no version/hash). Missing artifacts degrade gracefully: a check that
    cannot be grounded is skipped rather than guessed.
    """
    bundle_dir = Path(bundle_dir)
    diff_path = bundle_dir / "patch.diff"
    if not diff_path.exists():
        return []
    # Only the .nix package expression hunks — never embedded .patch payload — are
    # treated as metadata edits (see _nix_hunk_text).
    diff = _nix_hunk_text(diff_path.read_text())

    ref_path = bundle_dir / "upstream-ref.json"
    upstream_ref: dict = {}
    if ref_path.exists():
        try:
            upstream_ref = json.loads(ref_path.read_text())
        except (json.JSONDecodeError, OSError):
            upstream_ref = {}

    violations: list[MetadataViolation] = []

    old_ver, new_ver = _diff_new_version(diff)
    version_changed = new_ver is not None and new_ver != old_ver
    target_ver = _resolver_target_version(upstream_ref)
    resolver_src_hash = _resolver_src_hash(upstream_ref)
    added_src_hashes = _diff_added_src_hash_values(diff)

    # 1. diff version must match the resolver's target version.
    if new_ver and target_ver and new_ver != target_ver:
        violations.append(
            MetadataViolation(
                code="version-mismatch-vs-resolver",
                message=(
                    f"patch.diff bumps version to {new_ver!r} but "
                    f"upstream-ref.json.target_version is {target_ver!r}"
                ),
                evidence={"diff_version": new_ver, "target_version": target_ver},
            )
        )

    # 2 + 3. On a version bump the resolver's known-correct source hash MUST appear
    #    among the diff's added hash lines. Checking for PRESENCE of the grounded
    #    value (rather than classifying which diff `hash` is the source) sidesteps
    #    the bare-`hash` ambiguity and is sound in both directions: an honest bump
    #    always adds the prefetched hash, so this never false-rejects. Its absence
    #    means the source hash was left stale (no hash changed at all) or set to a
    #    wrong value (some hash changed, but not to the grounded one).
    if version_changed and resolver_src_hash and resolver_src_hash not in added_src_hashes:
        if _diff_has_hash_change(diff):
            violations.append(
                MetadataViolation(
                    code="wrong-src-hash",
                    message=(
                        "patch.diff bumps version but its source hash does not match "
                        "the prefetched upstream-ref.json src hash"
                    ),
                    evidence={"expected_src_hash": resolver_src_hash},
                )
            )
        else:
            violations.append(
                MetadataViolation(
                    code="version-without-hash",
                    message=(
                        f"version bumped {old_ver!r} -> {new_ver!r} but no source "
                        "hash changed in patch.diff"
                    ),
                    evidence={"old_version": old_ver, "new_version": new_ver},
                )
            )

    return violations
