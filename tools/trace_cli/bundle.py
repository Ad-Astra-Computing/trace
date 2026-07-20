"""`trace bundle assemble` + `trace bundle finalize` — glue the proven resolver-side pieces.

Per the user's design call: narrow v0 scope. This subcommand glues
already-supported pieces; it is NOT a general bundle factory and does
NOT call Patcher / Reviewer / Reproducer / Builder, NOR does it
synthesise Scout / Cartographer outputs. It only operates on what the
resolver-side modules already produce.

Pipeline:

    resolver-input.json (caller-supplied) ──► resolve()
                                              upstream-ref dict
    package.nix          (caller-supplied) ──► derive_prefetch_targets()
                                              targets[] + skipped[]
                                              ──► auto_prefetch_high_confidence()
                                                  prefetch_hashes[] (URL kind)
                                              ──► (optional) prefetch_go_mod_vendor()
                                                  prefetch_hashes[] (go-mod-vendor)
                                                  prefetch_skips[]   (failures)
                                              ──► merge into upstream-ref dict
    finding.json     ┐
    impact.json      │ caller-supplied (optional); copied verbatim
    maintainers.json ┘

Output (in --out directory):
    upstream-ref.json     — full, including prefetch_hashes[] and prefetch_skips[]
    package.nix           — copied verbatim
    resolver-input.json   — copied verbatim, for replay attribution
    finding.json          — if --finding supplied
    impact.json           — if --impact supplied
    maintainers.json      — if --maintainers supplied

What this command DOES NOT do (intentionally, per the user):
    * write bundle.json or replay.json (those need full Scout +
      Cartographer + Steward wiring; v0 leaves them to manual assembly)
    * invent finding.json / impact.json / maintainers.json from
      resolver-input.json
    * call Patcher or any model
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

from agents.upstream_ref_resolver import (
    FetchzipFailure,
    FetchzipRequest,
    FetchzipSuccess,
    GoModVendorFailure,
    GoModVendorRequest,
    GoModVendorSuccess,
    PrefetchTarget,
    derive_prefetch_targets,
    prefetch_fetchzip,
    prefetch_go_mod_vendor,
    prefetch_targets,
    resolve,
)


@dataclass(frozen=True)
class AssembleResult:
    """What was written + a structured summary suitable for human + JSON emit."""

    out_dir: Path
    cve_id: str
    eligibility_verdict: str
    target_version: str | None
    fix_tier: str | None
    files_written: list[str] = field(default_factory=list)
    prefetch_hashes_grounded: list[str] = field(default_factory=list)
    prefetch_skips: list[str] = field(default_factory=list)
    prefetch_failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "out_dir": str(self.out_dir),
            "cve_id": self.cve_id,
            "eligibility_verdict": self.eligibility_verdict,
            "target_version": self.target_version,
            "fix_tier": self.fix_tier,
            "files_written": list(self.files_written),
            "prefetch_hashes_grounded": list(self.prefetch_hashes_grounded),
            "prefetch_skips": list(self.prefetch_skips),
            "prefetch_failures": list(self.prefetch_failures),
        }


def assemble_bundle(
    *,
    resolver_input_path: Path,
    package_nix_path: Path,
    out_dir: Path,
    finding_path: Path | None = None,
    impact_path: Path | None = None,
    maintainers_path: Path | None = None,
    attr_path: str | None = None,
    nixpkgs_rev: str | None = None,
    run_go_mod_vendor: bool = False,
    run_fetchzip: bool = False,
    prefetch_url_fn=None,
    go_mod_vendor_runner=None,
    fetchzip_runner=None,
) -> AssembleResult:
    """Run the resolver-side pipeline end-to-end and write canonical artifacts.

    Args:
        resolver_input_path:  path to resolver-input.json.
        package_nix_path:     path to package.nix for the affected attr.
        out_dir:              output directory (created if missing).
        finding_path:         optional finding.json to copy in.
        impact_path:          optional impact.json to copy in.
        maintainers_path:     optional maintainers.json to copy in.
        attr_path:            optional attr name to use for derivation /
                              go-mod-vendor; falls back to resolver-input's
                              attr_path field if absent.
        nixpkgs_rev:          optional nixpkgs revision to pin during
                              go-mod-vendor extraction.
        run_go_mod_vendor:    when True, run go-mod-vendor for any
                              vendorHash slot the URL derivation skipped.
                              Default False because the build is slow and
                              network-touching.
        prefetch_url_fn:      swappable URL-prefetch runner (tests).
        go_mod_vendor_runner: swappable go-mod-vendor runner (tests).
    """
    input_doc = json.loads(resolver_input_path.read_text())
    upstream_ref = resolve(input_doc)
    cve_id = upstream_ref["cve_id"]
    verdict = upstream_ref["eligibility"]["verdict"]
    target_version = upstream_ref.get("target_version")
    fix_tier = upstream_ref.get("fix_tier")

    grounded_names: list[str] = []
    skip_descrs: list[str] = []
    failure_descrs: list[str] = []

    if verdict.startswith("eligible"):
        package_source = package_nix_path.read_text()
        attr = attr_path or input_doc.get("attr_path") or input_doc.get("attr")
        derivation = derive_prefetch_targets(
            upstream_ref=upstream_ref,
            package_source=package_source,
            attr_path=attr,
        )
        # High-confidence URL prefetch.
        high_targets = [t for t in derivation.targets if t.confidence == "high"]
        prefetch_inputs = [
            PrefetchTarget(name=t.name, url=t.url, algorithm=t.algorithm)
            for t in high_targets
        ]
        url_outcome = prefetch_targets(prefetch_inputs, prefetch_url_fn=prefetch_url_fn)

        # Optional fetchzip src.hash extraction for medium-confidence
        # github-release-archive / similar fetcher targets. Auto-prefetch
        # only fires for HIGH confidence; the fetchzip runner is the
        # right tool for fetchFromGitHub / fetchzip / fetchgit, where
        # `nix-prefetch-url`'s hash diverges from what the package's
        # actual fetcher demands.
        fz_successes: list[FetchzipSuccess] = []
        fz_failures: list[FetchzipFailure] = []
        if run_fetchzip and target_version:
            for t in derivation.targets:
                if t.name != "src.hash":
                    continue
                if t.confidence == "high":
                    continue  # already handled by URL prefetch
                if any(h.name == "src.hash" for h in url_outcome.hashes):
                    continue  # URL prefetch already grounded src.hash
                request = FetchzipRequest(
                    attr_path=attr or "",
                    target_version=target_version,
                    current_version=input_doc.get("current_version") or "",
                    nixpkgs_rev=nixpkgs_rev,
                )
                outcome = prefetch_fetchzip(
                    request, command_runner=fetchzip_runner,
                )
                if isinstance(outcome, FetchzipSuccess):
                    fz_successes.append(outcome)
                else:
                    fz_failures.append(outcome)
                break  # one src.hash slot per package

        # Optional go-mod-vendor for any vendorHash skip.
        gmv_successes: list[GoModVendorSuccess] = []
        gmv_failures: list[GoModVendorFailure] = []
        remaining_skips = list(derivation.skipped)
        if run_go_mod_vendor and target_version:
            src_hash = next(
                (h.value for h in url_outcome.hashes if h.name == "src.hash"),
                None,
            )
            for skip in derivation.skipped:
                if skip.name != "vendorHash":
                    continue
                request = GoModVendorRequest(
                    attr_path=attr or "",
                    target_version=target_version,
                    src_hash=src_hash,
                    nixpkgs_rev=nixpkgs_rev,
                )
                outcome = prefetch_go_mod_vendor(
                    request, command_runner=go_mod_vendor_runner,
                )
                if isinstance(outcome, GoModVendorSuccess):
                    gmv_successes.append(outcome)
                    # Drop the corresponding skip entry — now grounded.
                    remaining_skips = [s for s in remaining_skips if s.name != skip.name]
                else:
                    # Live attempt failed. Drop the skip entry (no longer
                    # accurate: the resolver DID attempt). The failure
                    # itself goes into prefetch_failures[] below, full
                    # attribution preserved.
                    gmv_failures.append(outcome)
                    remaining_skips = [
                        s for s in remaining_skips if s.name != skip.name
                    ]

        # Compose final upstream-ref.
        ph_entries: list[dict] = [h.to_dict() for h in url_outcome.hashes]
        ph_entries += [f.to_schema_dict() for f in fz_successes]
        ph_entries += [g.to_schema_dict() for g in gmv_successes]
        any_prefetch_field = False
        if ph_entries:
            upstream_ref["prefetch_hashes"] = ph_entries
            grounded_names = [e["name"] for e in ph_entries]
            any_prefetch_field = True
        if remaining_skips:
            upstream_ref["prefetch_skips"] = [s.to_schema_dict() for s in remaining_skips]
            skip_descrs = [f"{s.name}={s.reason}" for s in remaining_skips]
            any_prefetch_field = True
        if url_outcome.failures or gmv_failures or fz_failures:
            failures_list = list(url_outcome.failures_as_list())
            failures_list += [f.to_schema_dict() for f in fz_failures]
            failures_list += [_gmv_failure_to_prefetch_failures_entry(f) for f in gmv_failures]
            # Source-backport: the patch never changes src.hash (version is
            # unchanged by design). A src.hash prefetch failure is informational
            # only; marking it required_for_patch=True would mislead Reviewer
            # into a false rule-8 refusal. Correct the flag here at the producer
            # layer so the training data is unambiguous.
            is_source_backport = (
                upstream_ref.get("eligibility", {}).get("patch_strategy") == "source-backport"
            )
            if is_source_backport:
                for f in failures_list:
                    if f.get("name") == "src.hash":
                        f["required_for_patch"] = False
                        if "detail" in f:
                            f["detail"] = (f["detail"] + " source-backport: src.hash unchanged by patch.")[:2048]
            upstream_ref.setdefault("prefetch_failures", []).extend(failures_list)
            failure_descrs = [f"{f.name}={f.reason}" for f in url_outcome.failures]
            failure_descrs += [f"{f.name}={f.reason}" for f in fz_failures]
            failure_descrs += [f"{f.name}={f.reason}" for f in gmv_failures]
            any_prefetch_field = True
        # Schema-version bump: emitting any prefetch_* field requires 1.1.0
        # per the schema's allOf rule. Resolver itself emits 1.0.0; bundle
        # assemble is the layer that materialises the additive fields.
        if any_prefetch_field:
            upstream_ref["schema_version"] = "1.1.0"

    # Write artifacts.
    out_dir.mkdir(parents=True, exist_ok=True)
    files_written: list[str] = []

    upstream_ref_out = out_dir / "upstream-ref.json"
    upstream_ref_out.write_text(json.dumps(upstream_ref, indent=2) + "\n")
    files_written.append("upstream-ref.json")

    pkg_out = out_dir / "package.nix"
    shutil.copyfile(package_nix_path, pkg_out)
    files_written.append("package.nix")

    ri_out = out_dir / "resolver-input.json"
    shutil.copyfile(resolver_input_path, ri_out)
    files_written.append("resolver-input.json")

    # Seed a partial replay.json with just the upstream-ref-resolver
    # invocation that produced the upstream-ref.json we just wrote.
    # `bundle finalize` later promotes this to a full replay record by
    # adding the top-level bundle metadata (bundle_id, tool_manifest, etc.).
    import hashlib as _hashlib
    import uuid as _uuid
    upstream_ref_sha = _hashlib.sha256(upstream_ref_out.read_bytes()).hexdigest()
    # Resolver-input.json is the canonical input the resolver consumed;
    # finding.json (if supplied) is recorded as a secondary input. Either
    # way the inputs[] list is non-empty per the replay-schema.
    resolver_input_sha = _hashlib.sha256(ri_out.read_bytes()).hexdigest()
    seed_inputs = [{"path": "resolver-input.json", "sha256": resolver_input_sha}]
    if finding_path is not None:
        finding_sha = _hashlib.sha256(finding_path.read_bytes()).hexdigest()
        seed_inputs.insert(0, {"path": "finding.json", "sha256": finding_sha})
    seed_replay = {
        "roles": [{
            "role": "upstream-ref-resolver",
            "invocations": [{
                "invocation_id": str(_uuid.uuid4()),
                "role": "upstream-ref-resolver",
                "started_at": _utc_now_iso(),
                "ended_at": _utc_now_iso(),
                "model": {
                    "family": "deterministic-no-model",
                    "vendor": "internal",
                    "model_id": "upstream-ref-resolver-deterministic",
                    "version": "1.0.0",
                    "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
                },
                "prompt": {
                    "path": "prompts/upstream-ref-resolver.v1.md",
                    "sha256": "7" * 64,
                },
                "inputs": seed_inputs,
                "outputs": [{"path": "upstream-ref.json", "sha256": upstream_ref_sha}],
                "rng_seed": None,
                "validators_passed": ["eligibility-verdict-present"],
                "network_policy_applied": "feeds-only",
            }],
        }],
    }
    replay_out = out_dir / "replay.json"
    replay_out.write_text(json.dumps(seed_replay, indent=2) + "\n")
    files_written.append("replay.json (partial; complete with `bundle finalize`)")

    if finding_path is not None:
        shutil.copyfile(finding_path, out_dir / "finding.json")
        files_written.append("finding.json")
    if impact_path is not None:
        shutil.copyfile(impact_path, out_dir / "impact.json")
        files_written.append("impact.json")
    if maintainers_path is not None:
        shutil.copyfile(maintainers_path, out_dir / "maintainers.json")
        files_written.append("maintainers.json")

    return AssembleResult(
        out_dir=out_dir,
        cve_id=cve_id,
        eligibility_verdict=verdict,
        target_version=target_version,
        fix_tier=fix_tier,
        files_written=files_written,
        prefetch_hashes_grounded=grounded_names,
        prefetch_skips=skip_descrs,
        prefetch_failures=failure_descrs,
    )


def _gmv_failure_to_prefetch_failures_entry(failure: GoModVendorFailure) -> dict:
    """Translate a GoModVendorFailure into a schema-shape prefetch_failures[]
    entry. Preserves attempted_command + attempted_at + required_for_patch,
    which the previous skip-translation lost."""
    return {
        "name": failure.name,
        "reason": failure.reason,
        "required_for_patch": failure.required_for_patch,
        "tool": "nix-build",
        "attempted_command": failure.attempted_command,
        "detail": failure.detail[:2048],
        "attempted_at": failure.attempted_at,
    }


def emit_human_summary(result: AssembleResult) -> str:
    lines = [
        f"bundle assemble complete",
        f"  out_dir:               {result.out_dir}",
        f"  cve_id:                {result.cve_id}",
        f"  eligibility verdict:   {result.eligibility_verdict}",
        f"  target_version:        {result.target_version or '(n/a)'}",
        f"  fix_tier:              {result.fix_tier or '(n/a)'}",
        f"  files written:         {', '.join(result.files_written)}",
        f"  prefetch_hashes:       {', '.join(result.prefetch_hashes_grounded) or '(none)'}",
        f"  prefetch_skips:        {', '.join(result.prefetch_skips) or '(none)'}",
        f"  prefetch_failures:     {', '.join(result.prefetch_failures) or '(none)'}",
    ]
    return "\n".join(lines)


# ─── bundle finalize ──────────────────────────────────────────────────────


# Canonical bundle file set per policy/bundle-schema.json. Order is the
# write-order in existing bundle.json files; each entry carries the
# producer role and replay_critical flag the schema expects. Keep this
# table in sync with the schema if either evolves.
_CANONICAL_FILES: list[tuple[str, str, bool]] = [
    ("bundle.json",         "steward",               True),
    ("finding.json",        "scout",                 True),
    ("impact.json",         "cartographer",          True),
    ("maintainers.json",    "cartographer",          True),
    ("upstream-ref.json",   "upstream-ref-resolver", True),
    ("patch.diff",          "patcher",               True),
    ("patch-rationale.md",  "patcher",               True),
    ("passthru-tests.json", "reproducer",            True),
    ("reproducer.nix",      "reproducer",            True),
    ("reproducer-log.txt",  "reproducer",            False),
    ("reproducer-refusal.json", "reproducer",        True),
    ("build.json",          "builder",               False),
    ("review.md",           "reviewer",              True),
    ("review-refusal.json",       "reviewer",              True),
    ("review-scoring-report.json", "reviewer",             False),
    ("sbom-delta.json",           "upstream-ref-resolver", True),
    ("replay.json",         "steward",               True),
    ("provenance.jsonl",    "steward",               False),
    ("bundle.sig",          "steward",               False),
]

# Placeholder hash + bytes used for files not yet on disk. The schema
# permits any 64-hex string; using a recognisable filler (`d` * 64) makes
# it obvious during review that the file wasn't materialised yet.
_PLACEHOLDER_HASH = "d" * 64
_PLACEHOLDER_BYTES = 256


@dataclass(frozen=True)
class FinalizeResult:
    out_dir: Path
    bundle_id: str
    cve_id: str
    kind: str
    files_real_hash: list[str] = field(default_factory=list)
    files_placeholder: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "out_dir": str(self.out_dir),
            "bundle_id": self.bundle_id,
            "cve_id": self.cve_id,
            "kind": self.kind,
            "files_real_hash": list(self.files_real_hash),
            "files_placeholder": list(self.files_placeholder),
        }


class BundleSchemaError(ValueError):
    """A bundle document fails policy-schema validation at finalize time."""


# Resolver-side documents finalize validates against their policy schema before
# writing bundle.json. (bundle.json / replay.json are produced BY finalize and
# validated by the schema fixture test; build.json arrives post-cert.)
_FINALIZE_VALIDATED_DOCS = {
    "finding.json": "finding-schema.json",
    "impact.json": "impact-schema.json",
    "maintainers.json": "maintainers-schema.json",
    "upstream-ref.json": "upstream-ref-schema.json",
}


def _validate_bundle_docs(bundle_dir: Path) -> list[str]:
    """Validate each present resolver-side document against its policy schema.

    Returns a list of ``"<file>:<loc>: <message>"`` strings (empty == all valid).
    finalize refuses to write bundle.json when this is non-empty, so a
    schema-invalid bundle — a `prefetch_kind` outside the enum, disallowed extra
    prefetch fields (`nixpkgs_commit`/`note`), or a malformed impact/maintainers
    doc — is caught at CREATION rather than slipping onto a branch and failing CI
    later. (Added 2026-06-14 after ~10 concurrent sessions mass-committed bundles
    with exactly these defects; DECISIONS:47 had already documented the
    prefetch_kind='url'-not-'fetchurl' trap with no guardrail behind it.)

    Degrades gracefully: jsonschema/referencing are dev-shell deps, not base
    trace_cli deps. When finalize runs in a bare environment without them, SKIP
    validation (warn) instead of crashing — the CI schema fixture test remains the
    authoritative backstop. The guardrail is defense-in-depth that moves the catch
    left wherever the deps are present (nix dev shell, CI)."""
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError:
        import sys
        print("warning: jsonschema/referencing unavailable; skipping finalize "
              "doc-schema validation (CI schema fixture test still gates this bundle)",
              file=sys.stderr)
        return []

    policy_dir = Path(__file__).resolve().parents[2] / "policy"
    schemas: dict[str, dict] = {}
    for p in policy_dir.glob("*-schema.json"):
        try:
            schemas[p.name] = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            continue
    registry = Registry().with_resources(
        [(s["$id"], Resource.from_contents(s)) for s in schemas.values() if "$id" in s]
    )
    errors: list[str] = []
    for fname, sname in _FINALIZE_VALIDATED_DOCS.items():
        fp = bundle_dir / fname
        if not fp.is_file() or sname not in schemas:
            continue
        try:
            doc = json.loads(fp.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"{fname}: not valid JSON ({exc})")
            continue
        validator = Draft202012Validator(schemas[sname], registry=registry)
        for e in validator.iter_errors(doc):
            loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
            errors.append(f"{fname}:{loc}: {e.message}")
    return errors


def finalize_bundle(
    *,
    bundle_dir: Path,
    bundle_kind: str = "auto-merge",
    kind_reason: str | None = None,
    created_at: str | None = None,
    nixpkgs_rev: str | None = None,
    cve_id: str | None = None,
    auto_merge_evidence_path: str | None = None,
) -> FinalizeResult:
    """Compute file hashes + write bundle.json + replay.json.

    Reads upstream-ref.json (and finding.json if present) to populate
    cve_id / nixpkgs_rev when not supplied. Computes a deterministic
    bundle_id = sha256(cve_id || nixpkgs_rev || created_at)[:16].

    Writes:
      bundle.json   — real sha256 + bytes for every file on disk in the
                      canonical set; placeholder for files not yet
                      produced (patcher / reproducer / reviewer / etc.).
      replay.json   — top-level replay metadata + the upstream-ref-
                      resolver invocation seeded with the on-disk
                      upstream-ref.json sha. If a replay.json already
                      exists, its roles[] are preserved (assemble may
                      have written one).
    """
    import hashlib

    if not bundle_dir.is_dir():
        raise FileNotFoundError(f"bundle_dir does not exist: {bundle_dir}")

    # Guardrail: refuse to finalize a bundle whose resolver-side documents fail
    # policy-schema validation. Catches the recurring prefetch-pin defect
    # (prefetch_kind not in {url, go-mod-vendor, fetchzip}; nixpkgs_commit/note
    # extra fields) and malformed impact/maintainers at creation, not at CI.
    doc_errors = _validate_bundle_docs(bundle_dir)
    if doc_errors:
        raise BundleSchemaError(
            "bundle documents fail policy-schema validation; fix before finalize "
            "(prefetch_kind must be one of url/go-mod-vendor/fetchzip; no extra "
            "fields like nixpkgs_commit/note in prefetch_hashes[]):\n  "
            + "\n  ".join(doc_errors)
        )

    upstream_ref_path = bundle_dir / "upstream-ref.json"
    if not upstream_ref_path.is_file():
        raise FileNotFoundError(
            f"upstream-ref.json missing in {bundle_dir}; finalize requires "
            f"a previously-assembled bundle."
        )
    upstream_ref = json.loads(upstream_ref_path.read_text())

    if cve_id is None:
        cve_id = upstream_ref.get("cve_id")
    if cve_id is None:
        finding_path = bundle_dir / "finding.json"
        if finding_path.is_file():
            cve_id = json.loads(finding_path.read_text()).get("cve_id")
    if not cve_id:
        raise ValueError("could not determine cve_id from upstream-ref.json or finding.json")

    if nixpkgs_rev is None:
        impact_path = bundle_dir / "impact.json"
        if impact_path.is_file():
            nixpkgs_rev = json.loads(impact_path.read_text()).get("nixpkgs_rev")
        if nixpkgs_rev is None:
            # Fall back to a 40-zero placeholder (legal under bundle schema).
            nixpkgs_rev = "0" * 40

    # Placeholder/invalid nixpkgs_rev guardrail (codex 2026-06-15, after the
    # salvage-backport placeholder-rev bundles). The bundle-schema pattern
    # ^[0-9a-f]{40}$ ACCEPTS 40 zeros and impact.json.nixpkgs_rev is required, so the
    # real defect is an EXPLICIT all-zero rev (or one passed via --nixpkgs-rev), not
    # just the None-fallback. For a REAL-CVE bundle that is fatal to certification:
    # the cert workflow does `git fetch origin <rev>` and an all-zero rev cannot
    # resolve, so the bundle can never be cert-green and the readiness gate excludes
    # it from the training corpus. Warn loudly so a bootstrap notices at finalize,
    # not at CI. Synthetic CVE-0000-* fixtures use zero revs by design — exempt them.
    if cve_id and not cve_id.startswith("CVE-0000"):
        import re as _re
        if not _re.fullmatch(r"[0-9a-f]{40}", nixpkgs_rev or "") or set(nixpkgs_rev) == {"0"}:
            print(
                f"warning: {cve_id}: nixpkgs_rev is a placeholder/invalid value "
                f"({nixpkgs_rev[:12]!r}). This bundle CANNOT be certified (the cert "
                f"`git fetch origin <rev>` cannot resolve it) and will be EXCLUDED from "
                f"the training corpus. Set a real 40-hex impact.json.nixpkgs_rev or pass "
                f"--nixpkgs-rev.",
                file=sys.stderr,
            )

    if created_at is None:
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bundle_id = hashlib.sha256(
        f"{cve_id}|{nixpkgs_rev}|{created_at}".encode("utf-8")
    ).hexdigest()[:16]

    # Preserve auto_merge_evidence_path from existing bundle.json if not overridden.
    existing_bundle_path = bundle_dir / "bundle.json"
    if auto_merge_evidence_path is None and existing_bundle_path.is_file():
        try:
            existing_bundle = json.loads(existing_bundle_path.read_text())
            auto_merge_evidence_path = existing_bundle.get("auto_merge_evidence_path")
        except (json.JSONDecodeError, KeyError):
            pass

    # reviewer-attested bundles must not include reproducer / review-refusal files.
    _reviewer_attested_excluded = frozenset({
        "reproducer.nix", "reproducer-log.txt", "review-refusal.json",
    })

    files_block: dict[str, dict] = {}
    real_hash_names: list[str] = []
    placeholder_names: list[str] = []
    for fname, producer, replay_critical in _CANONICAL_FILES:
        if (
            auto_merge_evidence_path == "reviewer-attested"
            and fname in _reviewer_attested_excluded
        ):
            continue
        path = bundle_dir / fname
        if path.is_file() and fname != "bundle.json":
            data = path.read_bytes()
            files_block[fname] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "producer_role": producer,
                "replay_critical": replay_critical,
            }
            real_hash_names.append(fname)
        else:
            files_block[fname] = {
                "sha256": _PLACEHOLDER_HASH,
                "bytes": _PLACEHOLDER_BYTES,
                "producer_role": producer,
                "replay_critical": replay_critical,
            }
            placeholder_names.append(fname)

    # Optional replay-critical artifacts: manifested ONLY when actually on disk
    # (no placeholder for bundles that don't carry them, so a version-bump
    # bundle never claims a signed artifact that doesn't exist). upstream-fix.patch
    # is the source-backport ground-truth diff (the Patcher transcribes it and the
    # Reviewer verifies against it — replay-critical when present).
    for fname, producer in (("upstream-fix.patch", "upstream-ref-resolver"),):
        path = bundle_dir / fname
        if path.is_file():
            data = path.read_bytes()
            files_block[fname] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "producer_role": producer,
                "replay_critical": True,
            }
            real_hash_names.append(fname)

    # bundle.json's own entry is necessarily a placeholder — the file we
    # are about to write doesn't exist on disk yet, and self-hashing is
    # not meaningful.
    files_block["bundle.json"]["sha256"] = _PLACEHOLDER_HASH

    # bundle-schema requires kind_reason on every non-auto-merge bundle.
    # Default to a sensible value driven by upstream-ref's eligibility
    # signal AND impact.json's blast-radius signal so a finalize against
    # a fresh assemble output is schema-valid out of the box. Caller can
    # override via the --kind-reason flag when their workflow needs a
    # different code. Resolution order:
    #   1. impact.json.exceeds_threshold == true -> blast-radius-exceeds-threshold
    #      (trumps trigger because it's a measurable cap signal)
    #   2. eligibility.human_review_trigger -> matching code
    #   3. eligibility.verdict starts with "ineligible-" -> verbatim
    #   4. fallback: major-version-jump-requires-review (operator should override)
    if bundle_kind != "auto-merge" and kind_reason is None:
        impact_path = bundle_dir / "impact.json"
        impact_doc: dict = {}
        if impact_path.is_file():
            try:
                impact_doc = json.loads(impact_path.read_text())
            except json.JSONDecodeError:
                impact_doc = {}
        verdict = (upstream_ref.get("eligibility") or {}).get("verdict", "")
        trigger = (upstream_ref.get("eligibility") or {}).get("human_review_trigger", "")
        if impact_doc.get("exceeds_threshold") is True:
            kind_reason = "blast-radius-exceeds-threshold"
        elif trigger == "major-version-jump":
            kind_reason = "major-version-jump-requires-review"
        elif trigger == "ambiguous-changelog":
            kind_reason = "ambiguous-changelog-requires-review"
        elif trigger == "large-sbom-delta":
            kind_reason = "large-sbom-delta"
        elif trigger == "source-backport-experimental":
            kind_reason = "source-backport-experimental"
        elif trigger == "unparseable-version-comparison":
            kind_reason = "unparseable-version-comparison"
        elif verdict.startswith("ineligible-"):
            kind_reason = verdict
        else:
            kind_reason = "major-version-jump-requires-review"

    bundle_doc: dict[str, Any] = {
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "kind": bundle_kind,
        **({"kind_reason": kind_reason} if kind_reason else {}),
        **({"auto_merge_evidence_path": auto_merge_evidence_path}
           if auto_merge_evidence_path else {}),
        "created_at": created_at,
        "policy_version": "0" * 64,
        "bundle_schema_version": "1" * 64,
        "files": files_block,
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": "trace-dev@adastracomputing.com",
            "signed_files": [
                {"path": fname, "sha256": files_block[fname]["sha256"]}
                for fname, _, replay_critical in _CANONICAL_FILES
                if replay_critical and fname != "bundle.sig" and fname in files_block
            ] + [
                # Optional replay-critical artifacts present on disk (e.g.
                # upstream-fix.patch on source-backport bundles) must also be
                # signed, or Steward rule 4 rejects the bundle.
                {"path": fname, "sha256": files_block[fname]["sha256"]}
                for fname in ("upstream-fix.patch",)
                if fname in files_block and files_block[fname].get("replay_critical")
            ],
        },
    }

    (bundle_dir / "bundle.json").write_text(json.dumps(bundle_doc, indent=2) + "\n")

    # replay.json: preserve any existing roles[] (assemble may have seeded
    # an upstream-ref-resolver invocation), but rewrite the top-level
    # bundle metadata to match the freshly-computed bundle_id and pin
    # upstream-ref.json by its real sha.
    replay_path = bundle_dir / "replay.json"
    existing_roles: list = []
    if replay_path.is_file():
        try:
            existing_roles = json.loads(replay_path.read_text()).get("roles", [])
        except json.JSONDecodeError:
            existing_roles = []

    if not existing_roles:
        existing_roles = [_seed_resolver_invocation(bundle_dir, files_block)]
    else:
        # Keep the upstream-ref-resolver transcript consistent with the files the
        # downstream roles actually consumed — but ONLY for the legitimate
        # manual-curation case. assemble seeds this invocation with the
        # just-assembled upstream-ref.json hash; if the operator then pins a
        # prefetch hash (source=manual-pinned) and re-finalizes, the on-disk
        # upstream-ref.json sha changes but the seeded invocation still records the
        # stale one — a replay-transcript drift (codex review 2026-06-15). We
        # refresh the resolver invocation's recorded shas to match disk, gated on
        # the upstream-ref carrying a manual-pinned prefetch entry: that is the
        # intentional operator-curation signal. Without it we do NOT bless the edit
        # (an arbitrary/sloppy post-assemble upstream-ref change stays as drift so
        # replay verification can still flag it). NOTE: this makes the transcript
        # manifest-consistent, not a full provenance record; a future enhancement
        # (codex) is a curated_from_sha256 / manual-curation marker for adversarial
        # replay-audit. The manual-pin remains self-documented by source=="manual-pinned".
        _manual_pinned = any(
            (h or {}).get("source") == "manual-pinned"
            for h in (upstream_ref.get("prefetch_hashes") or [])
        )
        if _manual_pinned:
            _refresh_resolver_invocation_hashes(existing_roles, files_block)

    replay_doc = {
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [
                {"name": "python", "version": "3.13"},
                {"name": "trace-cli", "version": "0.0.0"},
            ],
        },
        "cross_family_rule_honored": True,
        "roles": existing_roles,
    }
    replay_path.write_text(json.dumps(replay_doc, indent=2) + "\n")

    return FinalizeResult(
        out_dir=bundle_dir,
        bundle_id=bundle_id,
        cve_id=cve_id,
        kind=bundle_kind,
        files_real_hash=real_hash_names,
        files_placeholder=placeholder_names,
    )


# Only these upstream-ref-resolver input/output paths are refreshed by
# _refresh_resolver_invocation_hashes — an explicit allowlist so the trust
# boundary is narrow and obvious (codex review 2026-06-15): the resolver's
# finding.json input and its upstream-ref.json / upstream-fix.patch outputs.
_RESOLVER_REFRESHABLE = frozenset({"finding.json", "upstream-ref.json", "upstream-fix.patch"})


def _refresh_resolver_invocation_hashes(roles: list, files_block: dict) -> None:
    """Update the upstream-ref-resolver invocation's recorded sha256s for the
    allowlisted resolver paths (`_RESOLVER_REFRESHABLE`) to match the final
    files_block, so the replay transcript stays consistent with the on-disk files
    after a manual prefetch pin + re-finalize. In-place; touches ONLY the
    upstream-ref-resolver role and ONLY the allowlisted paths."""
    for role in roles:
        if role.get("role") != "upstream-ref-resolver":
            continue
        for inv in role.get("invocations", []):
            for ref in inv.get("inputs", []) + inv.get("outputs", []):
                name = ref.get("path")
                if name in _RESOLVER_REFRESHABLE and name in files_block:
                    ref["sha256"] = files_block[name]["sha256"]


def _seed_resolver_invocation(bundle_dir: Path, files_block: dict) -> dict:
    """Construct a minimal upstream-ref-resolver invocation record when no
    replay.json was assembled previously. Used by `finalize` standalone."""
    finding_sha = files_block.get("finding.json", {}).get("sha256", _PLACEHOLDER_HASH)
    upstream_sha = files_block["upstream-ref.json"]["sha256"]
    return {
        "role": "upstream-ref-resolver",
        "invocations": [
            {
                "invocation_id": "00000000-0000-4000-8000-000000000000",
                "role": "upstream-ref-resolver",
                "started_at": "2026-04-27T00:00:00Z",
                "ended_at": "2026-04-27T00:00:01Z",
                "model": {
                    "family": "deterministic-no-model",
                    "vendor": "internal",
                    "model_id": "upstream-ref-resolver-deterministic",
                    "version": "1.0.0",
                    "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
                },
                "prompt": {
                    "path": "prompts/upstream-ref-resolver.v1.md",
                    "sha256": "7" * 64,
                },
                "inputs": [
                    {"path": "finding.json", "sha256": finding_sha},
                ],
                "outputs": [
                    {"path": "upstream-ref.json", "sha256": upstream_sha},
                ] + (
                    # source-backport: the resolver also supplies the upstream
                    # fix diff (ground truth) — record it as a resolver output so
                    # replay/provenance can attribute the signed artifact.
                    [{"path": "upstream-fix.patch",
                      "sha256": files_block["upstream-fix.patch"]["sha256"]}]
                    if "upstream-fix.patch" in files_block else []
                ),
                "rng_seed": None,
                "validators_passed": ["eligibility-verdict-present"],
                "network_policy_applied": "feeds-only",
            },
        ],
    }


def emit_finalize_summary(result: FinalizeResult) -> str:
    return "\n".join([
        "bundle finalize complete",
        f"  out_dir:               {result.out_dir}",
        f"  bundle_id:             {result.bundle_id}",
        f"  cve_id:                {result.cve_id}",
        f"  kind:                  {result.kind}",
        f"  real-hashed files:     {', '.join(result.files_real_hash) or '(none)'}",
        f"  placeholder files:     {', '.join(result.files_placeholder) or '(none)'}",
    ])


__all__ = [
    "AssembleResult",
    "FinalizeResult",
    "assemble_bundle",
    "emit_human_summary",
    "emit_finalize_summary",
    "finalize_bundle",
]
