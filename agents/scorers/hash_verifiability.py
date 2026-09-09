"""Scorer: hash-verifiability.

Closes the gap surfaced by the first live Patcher run (CVE-2026-25949):
schema-valid, upstream-cited, minimal patches can still ship hashes the
model cannot ground-truth — `lib.fakeHash` literal expansions, missing
`vendorHash` updates after a version bump, etc. Surface-contract scorers
gave that run a 1.0 composite even though the patch was non-buildable.

This scorer enforces refusal rule 8 from `prompts/patcher.v1.md` at the
artifact layer:

  * For a patch-shape invocation: parse `patch.diff` and check every
    hash-shaped value introduced (added line containing `hash =`,
    `*Hash =`, `*Sha256 =`, `*Sha512 =`) against the forbidden-pattern
    set. Also detect *silent omission*: if `version = ...` was bumped,
    every hash-shaped attribute that exists in the original
    `package.nix` and was NOT updated in the diff counts as ungrounded.
  * For a refusal-shape invocation citing rule 8: this is the
    contract-correct outcome — applies=True, score=1.0.
  * For a refusal under any other rule: applies=True, score=1.0 — a
    refusal emits no hashes, so by construction it cannot violate the
    grounded-hash rule. The note records that hash-verifiability was
    trivially satisfied rather than explicitly invoked.

Forbidden hash values (mirrors patcher.v1.md rule 8 verbatim):
  - Symbol references: `lib.fakeHash`, `lib.fakeSha256`, `lib.fakeSha512`
  - Literal `lib.fakeHash` expansion: `sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
  - Generalised SRI placeholder family: `sha256-A+=`, `sha512-A+=`
  - 64-character all-zero string (literal `lib.fakeSha256`)
  - 128-character all-zero string (literal `lib.fakeSha512`)
  - Empty string `""`

Refusal under rule 8 is the contract-correct outcome when at least one
required hash cannot be grounded; the scorer recognises it as a pass
rather than excluding it from the denominator. This keeps the composite
honest when comparing model behaviours: "refused for the right reason"
and "produced a verified patch" both score 1.0; only "produced a patch
with ungrounded hashes" scores below 1.0.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


# Hash-shaped attribute names worth checking. Matched case-sensitively
# against the LHS of `<name> = <value>;` assignments in patch.diff. Order
# is documentation-only; the regex matches any of these.
HASH_ATTR_NAMES: tuple[str, ...] = (
    "hash",
    "sha256",
    "sha512",
    "vendorHash",
    "vendorSha256",
    "cargoHash",
    "cargoSha256",
    "npmDepsHash",
    "pnpmDepsHash",
    "yarnDepsHash",
    "yarnHash",
    "outputHash",
    "outputHashAlgo",
)

# Forbidden symbol references — these are nixpkgs `lib` placeholders the
# Patcher must not emit per rule 8.
FORBIDDEN_SYMBOLS: frozenset[str] = frozenset(
    {
        "lib.fakeHash",
        "lib.fakeSha256",
        "lib.fakeSha512",
        "pkgs.lib.fakeHash",
        "pkgs.lib.fakeSha256",
        "pkgs.lib.fakeSha512",
    }
)

# Regex catching the SRI-form fake-hash family. `lib.fakeHash` literally
# expands to "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", and any
# similar `sha256-A+=` / `sha512-A+=` is the same intent.
_SRI_FAKE_RE = re.compile(r'^"?sha(256|512)-A+=?"?$')

# Regex for hex-form fake hashes. `lib.fakeSha256` is 64 zeros;
# `lib.fakeSha512` is 128 zeros. Allow surrounding quotes either way.
_HEX_FAKE_RE = re.compile(r'^"?(0{64}|0{128})"?$')

# Match a Nix-attribute assignment whose name is one of HASH_ATTR_NAMES,
# anchoring on indent + name + `=`. Captures the (raw) value through `;`
# or end-of-line. Examples it must catch:
#   hash = "sha256-...";
#   vendorHash = "sha256-AAAA=";
#   sha256 = "0000...";
#   hash = lib.fakeHash;
_HASH_ASSIGN_RE = re.compile(
    r"^\s*(?P<name>"
    + "|".join(re.escape(n) for n in HASH_ATTR_NAMES)
    + r")\s*=\s*(?P<value>[^;]+?);",
    re.MULTILINE,
)

# Match the `version = "X.Y.Z";` line so we can detect a bump in the diff.
_VERSION_ASSIGN_RE = re.compile(
    r'^\s*version\s*=\s*"(?P<value>[^"]+)"\s*;', re.MULTILINE
)


class HashVerifiabilityScorer:
    name = "hash-verifiability"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        out_paths = {o["path"] for o in invocation.get("outputs") or []}

        # Refusal path: contract-correct outcome when rule 8 was the cause;
        # trivially satisfied for any other refusal rule (no hashes emitted).
        if "refusal.json" in out_paths:
            return self._score_refusal(bundle_dir)

        # Patch path.
        return self._score_patch(bundle_dir)

    def _score_refusal(self, bundle_dir: Path) -> ScorerResult:
        ref_path = bundle_dir / "refusal.json"
        if not ref_path.is_file():
            return ScorerResult(
                self.name,
                self.version,
                applies=False,
                advisory=False,
                score=None,
                notes="refusal recorded in invocation but refusal.json not on disk",
            )
        try:
            ref = json.loads(ref_path.read_text())
        except json.JSONDecodeError as exc:
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=False,
                score=0.0,
                notes=f"refusal.json is not valid JSON: {exc}",
            )
        rule = ref.get("rule")
        if rule == 8:
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=False,
                score=1.0,
                notes="refusal under rule 8 (ungrounded hashes) — "
                "contract-correct outcome",
                details={"refusal_kind": "rule-8"},
            )
        return ScorerResult(
            self.name,
            self.version,
            applies=True,
            advisory=False,
            score=1.0,
            notes=(
                f"refusal under rule {rule!r}; no hashes were emitted, "
                f"so hash-verifiability is trivially satisfied"
            ),
            details={"refusal_kind": "non-rule-8", "rule": rule},
        )

    def _score_patch(self, bundle_dir: Path) -> ScorerResult:
        diff_path = bundle_dir / "patch.diff"
        if not diff_path.is_file():
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=False,
                score=0.0,
                notes="patch.diff not on disk",
            )
        diff_text = diff_path.read_text()

        added_lines = _added_lines(diff_text)
        added_text = "\n".join(added_lines)

        # Pull the prefetch_hashes[] table from upstream-ref.json. The Patcher
        # is permitted to emit a hash value ONLY if it appears in this table.
        # When the table is PRESENT, the scorer enforces strict matching: any
        # non-forbidden value not on the list scores as `not-in-prefetch-list`.
        # When the table is ABSENT (pre-prefetch v0 bundles), the scorer
        # falls back to forbidden-pattern checking only — anything not
        # forbidden is accepted as `grounded`. This keeps the three existing
        # corpus runs (traefik / mbedtls / bind) backward-compatible.
        upstream_ref_path = bundle_dir / "upstream-ref.json"
        prefetch_values: set[str] = set()
        prefetch_table_present = False
        if upstream_ref_path.is_file():
            try:
                upstream_ref = json.loads(upstream_ref_path.read_text())
            except json.JSONDecodeError:
                upstream_ref = {}
            ph = upstream_ref.get("prefetch_hashes")
            if isinstance(ph, list):
                prefetch_table_present = True
                for entry in ph:
                    v = entry.get("value") if isinstance(entry, dict) else None
                    if isinstance(v, str) and v:
                        prefetch_values.add(v)

        # Find every hash-shaped assignment introduced in the added lines.
        introduced: list[dict[str, Any]] = []
        for m in _HASH_ASSIGN_RE.finditer(added_text):
            name = m.group("name")
            value = m.group("value").strip()
            verdict = _classify_hash_value(value)
            # When the prefetch table is present, classify non-forbidden
            # values strictly against it.
            if verdict == "grounded" and prefetch_table_present:
                bare = value.strip('"').strip("'")
                if bare in prefetch_values:
                    verdict = "grounded-prefetch"
                else:
                    verdict = "not-in-prefetch-list"
            introduced.append({"attr": name, "value": value, "verdict": verdict})

        # Detect silent omission: if `version =` was bumped in the diff,
        # check that every hash-shaped attribute present in the ORIGINAL
        # package.nix that was associated with the bumped derivation is
        # also touched by the diff. Untouched hash attrs after a version
        # bump are ungrounded (the diff is implying they didn't change,
        # but a real version bump almost always invalidates them).
        #
        # Exception: if the prefetch table is present and the attr's
        # current value in package.nix already matches a grounded prefetch
        # value, the attr is implicitly correct — the model correctly left
        # it unchanged because the dependency content didn't change across
        # the version bump (e.g. vendorHash stays the same when Go vendor
        # modules are unaffected by the CVE fix).
        version_bumped = _diff_changes_version(diff_text)
        omitted_attrs: list[str] = []
        if version_bumped:
            pkg_path = bundle_dir / "package.nix"
            if pkg_path.is_file():
                original = pkg_path.read_text()
                # Build a map of attr_name -> current_value from original package.nix.
                original_hash_map: dict[str, str] = {}
                for m in _HASH_ASSIGN_RE.finditer(original):
                    original_hash_map[m.group("name")] = m.group("value").strip()
                original_hash_attrs = set(original_hash_map)
                touched_attrs = {entry["attr"] for entry in introduced}
                # Also include attrs touched on the removed side (some
                # diffs delete an entry then re-add a different attr).
                removed_lines = _removed_lines(diff_text)
                removed_text = "\n".join(removed_lines)
                touched_attrs |= {
                    m.group("name") for m in _HASH_ASSIGN_RE.finditer(removed_text)
                }
                candidate_omissions = original_hash_attrs - touched_attrs
                # Filter out attrs whose current value is already grounded
                # against the prefetch table (i.e. deliberately unchanged).
                for attr in sorted(candidate_omissions):
                    if prefetch_table_present:
                        current_value = original_hash_map.get(attr, "")
                        bare = current_value.strip('"').strip("'")
                        if bare in prefetch_values:
                            # Current value matches a grounded prefetch hash;
                            # leaving it untouched is correct — not an omission.
                            continue
                    omitted_attrs.append(attr)
                omitted_attrs = sorted(omitted_attrs)

        # Tally: every introduced hash whose verdict is not in the grounded
        # set is a violation; every omitted hash after a version bump is a
        # violation. Score is 1 - violations / required_count, floored at 0.
        # A patch that touches no hashes and bumps no version is vacuously
        # a pass.
        grounded_verdicts = {"grounded", "grounded-prefetch"}
        violations: list[dict[str, Any]] = []
        for entry in introduced:
            if entry["verdict"] not in grounded_verdicts:
                violations.append(
                    {
                        "kind": entry["verdict"],
                        "attr": entry["attr"],
                        "value": entry["value"],
                    }
                )
        for attr in omitted_attrs:
            violations.append({"kind": "silent-omission", "attr": attr, "value": None})

        required_count = len(introduced) + len(omitted_attrs)
        if required_count == 0:
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=False,
                score=1.0,
                notes="patch touches no hashes and bumps no version; "
                "hash-verifiability is vacuously satisfied",
                details={"introduced": [], "omitted_attrs": [], "violations": []},
            )

        score = max(0.0, 1.0 - len(violations) / required_count)
        if violations:
            kinds_seen = sorted({v["kind"] for v in violations})
            note = (
                f"{len(violations)}/{required_count} hash slots failed "
                f"verifiability (kinds: {', '.join(kinds_seen)}). "
                f"Per refusal rule 8, the Patcher should have refused "
                f"rather than emitting these."
            )
        else:
            note = (
                f"{required_count}/{required_count} hash slots verifiable: "
                f"every introduced hash matches a non-fake pattern and "
                f"no required hash was silently omitted across the version bump"
            )

        return ScorerResult(
            self.name,
            self.version,
            applies=True,
            advisory=False,
            score=score,
            notes=note,
            details={
                "version_bumped": version_bumped,
                "prefetch_table_present": prefetch_table_present,
                "prefetch_values_count": len(prefetch_values),
                "introduced": introduced,
                "omitted_attrs": omitted_attrs,
                "violations": violations,
                "required_count": required_count,
            },
        )


def _classify_hash_value(value: str) -> str:
    """Classify a hash-attr RHS as grounded / forbidden-symbol / forbidden-sri /
    forbidden-zero / forbidden-empty. Anything not on the forbidden list is
    treated as grounded (i.e. the model ground-truthed it from somewhere)."""
    v = value.strip()
    if v in FORBIDDEN_SYMBOLS:
        return "forbidden-symbol"
    if v == '""' or v == "''":
        return "forbidden-empty"
    if _SRI_FAKE_RE.match(v):
        return "forbidden-sri-fake"
    if _HEX_FAKE_RE.match(v):
        return "forbidden-zero-hash"
    return "grounded"


def _added_lines(diff_text: str) -> list[str]:
    """Return the lines added by the diff (those starting with `+` but not `+++`)."""
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            out.append(line[1:])
    return out


def _removed_lines(diff_text: str) -> list[str]:
    """Return the lines removed by the diff (those starting with `-` but not `---`)."""
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("---"):
            continue
        if line.startswith("-"):
            out.append(line[1:])
    return out


def _diff_changes_version(diff_text: str) -> bool:
    """True iff a `version = "..."` assignment appears on EITHER the + or - side."""
    added = "\n".join(_added_lines(diff_text))
    removed = "\n".join(_removed_lines(diff_text))
    return bool(_VERSION_ASSIGN_RE.search(added) or _VERSION_ASSIGN_RE.search(removed))
