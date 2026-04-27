"""`trace bundle assemble` — glue the proven resolver-side pieces.

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.upstream_ref_resolver import (
    GoModVendorFailure,
    GoModVendorRequest,
    GoModVendorSuccess,
    PrefetchTarget,
    derive_prefetch_targets,
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
    prefetch_url_fn=None,
    go_mod_vendor_runner=None,
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
        if url_outcome.failures or gmv_failures:
            failures_list = list(url_outcome.failures_as_list())
            failures_list += [_gmv_failure_to_prefetch_failures_entry(f) for f in gmv_failures]
            upstream_ref.setdefault("prefetch_failures", []).extend(failures_list)
            failure_descrs = [f"{f.name}={f.reason}" for f in url_outcome.failures]
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


__all__ = [
    "AssembleResult",
    "assemble_bundle",
    "emit_human_summary",
]
