"""Builder dispatcher.

Orchestrates the four operations locked in `docs/BUILDER_V1.md` §2:

  1. patch-apply         (apply patch.diff to package.nix)
  2. patched-build       (nix-build the patched derivation)
  3. reproducer-runs     (unpatched + patched contexts)
  4. passthru-tests-enumeration

Builds the build.json document of the §3 shape and returns a structured
result the executor writes to disk.

Builder is DETERMINISTIC. No model call. The `BuildRunner` Protocol
handles the actual nix-build invocations; the orchestration logic
below is testable with `FakeBuildRunner`.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.builder.protocol import (
    BuildOutcome,
    BuildRunner,
    INLINE_STDOUT_STDERR_CAP_BYTES,
    truncate_to_inline_cap,
)


SCHEMA_VERSION = "1.0.0"
BUILDER_ID = "trace-builder-v0.1.0"


# ─── result types ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BuilderRunResult:
    """Structured result the executor writes to bundle/build.json + replay."""

    build_json: dict[str, Any]
    dispatch_outcome: str
    full_logs: dict[str, str] = field(default_factory=dict)
    """Full untruncated stdout+stderr per phase. Keys: 'patched_build',
    'unpatched', 'patched'. Each value is the raw collected log; the
    executor persists oversize logs to bundle/build.log and records
    `stdout_stderr_log_sha256` on the corresponding phase block."""


# ─── orchestration entry point ────────────────────────────────────────────


def run_builder(
    *,
    bundle_dir: Path,
    build_runner: BuildRunner,
    nixpkgs_checkout: Path | None = None,
    apply_patch: bool = True,
    timeout_seconds_per_build: int = 1800,
    host_info: dict[str, str] | None = None,
    now_utc_iso: str | None = None,
) -> BuilderRunResult:
    """Run the four Builder operations in order; assemble build.json.

    Args:
        bundle_dir:          path to the finalized bundle directory
        build_runner:        BuildRunner Protocol implementation
                             (FakeBuildRunner for tests, LocalNixBuildRunner
                             on a Linux host)
        nixpkgs_checkout:    working copy of nixpkgs at finding.json's
                             nixpkgs_rev. None means "skip patch-apply
                             and use the bundle's package.nix directly"
                             — useful for FakeBuildRunner-driven tests
                             that don't need a real nixpkgs tree.
        apply_patch:         when False, skip the patch-apply phase and
                             record `applied: false` with reason
                             `skipped-by-orchestrator`. Used by the
                             executor when the bundle is in a state
                             where applying makes no sense (e.g.,
                             refusal-only).
        timeout_seconds_per_build: per-invocation timeout passed to the
                             BuildRunner.
        host_info:           {"system": ..., "nix_version": ...,
                             "tool_version": ...}. Populated by the
                             executor; defaults provided for tests.
        now_utc_iso:         override the started_at/ended_at clock for
                             deterministic tests.

    Returns:
        BuilderRunResult with the assembled build.json + full logs.
    """
    started_at = now_utc_iso or _utc_now_iso()
    started_clock = time.monotonic()

    finding = _read_json(bundle_dir / "finding.json") or {}
    cve_id = finding.get("cve_id") or ""
    affected = finding.get("affected") or []
    attr = (
        affected[0].get("attr_path")
        if affected and isinstance(affected[0], dict)
        else None
    )
    bundle = _read_json(bundle_dir / "bundle.json") or {}
    bundle_id = bundle.get("bundle_id") or ""
    nixpkgs_rev = bundle.get("nixpkgs_rev") or finding.get("nixpkgs_rev") or ""

    host = host_info or _default_host_info()

    instrumentation_path = bundle_dir / "reproducer-instrumentation.json"
    instrumentation, disable_doCheck, instrumentation_error = _read_instrumentation(
        instrumentation_path,
    )
    if instrumentation_error is not None:
        return _instrumentation_malformed_result(
            cve_id=cve_id, bundle_id=bundle_id, nixpkgs_rev=nixpkgs_rev,
            host=host, started_at=started_at,
            reason=instrumentation_error,
        )

    patch_diff_path = bundle_dir / "patch.diff"
    refusal_path = bundle_dir / "refusal.json"
    has_patch = patch_diff_path.is_file() and not refusal_path.is_file()

    reproducer_nix_path = bundle_dir / "reproducer.nix"
    reproducer_refusal_path = bundle_dir / "reproducer-refusal.json"
    has_reproducer = (
        reproducer_nix_path.is_file()
        and not reproducer_refusal_path.is_file()
    )

    # ── §2.1. patch-presence check ──────────────────────────────────────
    # patch_apply itself happens later (§2.2b), AFTER the unpatched
    # reproducer-run, so that unpatched.test evaluates against the
    # PRE-patch nixpkgs tree. See F7 / DECISIONS 2026-05-17.
    if not has_patch:
        patch_apply = _patch_apply_skipped("no-patch-or-patcher-refused")
        return _refused_result(
            cve_id=cve_id, bundle_id=bundle_id, nixpkgs_rev=nixpkgs_rev,
            host=host, started_at=started_at,
            patch_apply=patch_apply,
            dispatch_outcome="refused-no-patch",
            instrumentation=instrumentation,
        )

    # ── §2.2a. unpatched reproducer (PRE-patch tree) ────────────────────
    # `pkgs.<attr>` in the unpatched override must resolve against the
    # bundle's pinned nixpkgs at its UNMODIFIED state — without the
    # trace `patch.diff` applied yet. This is the F7 fix: when patch.diff
    # drops a nixpkgs-side patch that the prior version still needed,
    # the unpatched reconstruction must see the pre-drop patches list.
    if has_reproducer:
        unpatched_outcome = build_runner.run(
            nix_expression=_repro_nix_expression(
                reproducer_nix_path, attr_in_repro="unpatched.test",
                nixpkgs_pin=nixpkgs_checkout,
            ),
            cwd=nixpkgs_checkout if nixpkgs_checkout else bundle_dir,
            timeout_seconds=timeout_seconds_per_build,
            instrumentation=instrumentation,
        )
        unpatched_phase, unpatched_full = _build_phase_block(
            unpatched_outcome, applied=True, attr="unpatched.test",
        )
    else:
        unpatched_phase = {
            "applied": False,
            "outcome": "skipped",
            "exit_code": None,
            "drv_path": None,
            "out_path": None,
            "elapsed_seconds": None,
            "stdout_stderr": "",
            "stdout_stderr_log_sha256": None,
            "reason": "no-reproducer-or-reproducer-refused",
        }
        unpatched_full = ""

    # ── §2.2b. patch-apply ──────────────────────────────────────────────
    if not apply_patch or nixpkgs_checkout is None:
        patch_apply = {
            "applied": False,
            "git_apply_exit_code": None,
            "files_changed": [],
            "post_apply_sha": None,
            "reason": "skipped-by-orchestrator",
        }
    else:
        patch_apply = _apply_patch(
            patch_diff_path=patch_diff_path,
            nixpkgs_checkout=nixpkgs_checkout,
            attr=attr,
        )
        if not patch_apply.get("applied"):
            return _patch_apply_failed_result(
                cve_id=cve_id, bundle_id=bundle_id, nixpkgs_rev=nixpkgs_rev,
                host=host, started_at=started_at,
                patch_apply=patch_apply,
                unpatched_phase=unpatched_phase,
                unpatched_full=unpatched_full,
                instrumentation=instrumentation,
            )

    # ── §2.3. patched-build (POST-patch tree) ───────────────────────────
    # When disable_doCheck=true (reproducer-instrumentation.json knob, per
    # docs/REPRODUCER_V1.md §2.7), wrap the attr in an overrideAttrs
    # expression that turns off the check phase. The CVE-class regression
    # dimension is covered by §2.4's patched-reproducer run; patched-build
    # is just a build-succeeds sanity phase, and a 30+ minute check suite
    # is wasted CI time for slow-check packages like libtiff.
    if attr:
        if disable_doCheck:
            patched_outcome = build_runner.run(
                nix_expression=_no_check_expression(attr),
                cwd=nixpkgs_checkout if nixpkgs_checkout else bundle_dir,
                timeout_seconds=timeout_seconds_per_build,
            )
        else:
            patched_outcome = build_runner.run(
                attr=attr,
                cwd=nixpkgs_checkout if nixpkgs_checkout else bundle_dir,
                timeout_seconds=timeout_seconds_per_build,
            )
    else:
        patched_outcome = _no_attr_outcome()
    patched_build_phase, patched_build_full = _build_phase_block(
        patched_outcome, applied=True, attr=attr,
    )

    # ── §2.4. patched reproducer (POST-patch tree) ──────────────────────
    if has_reproducer:
        patched_repro_outcome = build_runner.run(
            nix_expression=_repro_nix_expression(
                reproducer_nix_path, attr_in_repro="patched.test",
                nixpkgs_pin=nixpkgs_checkout,
            ),
            cwd=nixpkgs_checkout if nixpkgs_checkout else bundle_dir,
            timeout_seconds=timeout_seconds_per_build,
            instrumentation=instrumentation,
        )
        patched_repro_phase, patched_repro_full = _build_phase_block(
            patched_repro_outcome, applied=True, attr="patched.test",
        )
    else:
        patched_repro_phase = dict(unpatched_phase)
        patched_repro_full = ""

    # ── §2.4. passthru-tests-enumeration ────────────────────────────────
    if attr and nixpkgs_checkout:
        ground_truth = _enumerate_passthru_tests(
            build_runner=build_runner,
            attr=attr,
            cwd=nixpkgs_checkout,
            timeout_seconds=timeout_seconds_per_build,
        )
    else:
        ground_truth = []

    ended_at = _utc_now_iso()

    dispatch_outcome = "ok"
    if not has_reproducer:
        dispatch_outcome = "refused-no-reproducer"

    build_json: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "bundle_id": bundle_id,
        "nixpkgs_rev": nixpkgs_rev,
        "builder_id": BUILDER_ID,
        "host": dict(host),
        "started_at": started_at,
        "ended_at": ended_at,
        "patch_apply": patch_apply,
        "patched_build": patched_build_phase,
        "unpatched": unpatched_phase,
        "patched": patched_repro_phase,
        "passthru_tests_ground_truth": ground_truth,
        "sbom_delta_attempted": False,
        "dispatch_outcome": dispatch_outcome,
        "instrumentation": instrumentation,
    }

    return BuilderRunResult(
        build_json=build_json,
        dispatch_outcome=dispatch_outcome,
        full_logs={
            "patched_build": patched_build_full,
            "unpatched": unpatched_full,
            "patched": patched_repro_full,
        },
    )


# ─── per-phase helpers ────────────────────────────────────────────────────


def _build_phase_block(
    outcome: BuildOutcome,
    *,
    applied: bool,
    attr: str | None,
) -> tuple[dict[str, Any], str]:
    """Build a phase dict per `docs/BUILDER_V1.md` §3 from a BuildOutcome.

    Returns (phase_dict, full_stdout_stderr). The caller writes the full
    log to `build.log` if it exceeds the inline cap; the phase dict
    holds only the truncated tail.
    """
    full = outcome.stdout_stderr or ""
    truncated, was_truncated = truncate_to_inline_cap(full)
    if outcome.timed_out:
        outcome_value: str | None = "timed-out"
    elif outcome.exit_code is None:
        outcome_value = "skipped" if not applied else None
    elif outcome.exit_code == 0:
        outcome_value = "succeeded"
    else:
        outcome_value = "failed"
    phase: dict[str, Any] = {
        "applied": applied,
        "outcome": outcome_value,
        "exit_code": outcome.exit_code,
        "drv_path": outcome.drv_path,
        "out_path": outcome.out_path,
        "elapsed_seconds": round(outcome.elapsed_seconds, 3) if outcome.elapsed_seconds is not None else None,
        "stdout_stderr": truncated,
        "stdout_stderr_log_sha256": _sha256(full) if was_truncated else None,
    }
    if outcome.extras.get("reason"):
        phase["reason"] = outcome.extras["reason"]
    return phase, full


def _no_attr_outcome() -> BuildOutcome:
    return BuildOutcome(
        exit_code=None, drv_path=None, out_path=None,
        stdout_stderr="finding.json had no affected[0].attr_path; cannot run patched-build",
        elapsed_seconds=0.0,
        extras={"reason": "no-attr"},
    )


# ─── §2.1: patch-apply ───────────────────────────────────────────────────


def _apply_patch(
    *,
    patch_diff_path: Path,
    nixpkgs_checkout: Path,
    attr: str | None,
) -> dict[str, Any]:
    """Apply patch.diff to nixpkgs_checkout via `git apply`.

    The patch.diff in a bundle uses bundle-relative paths
    (e.g. `--- a/package.nix`), not nixpkgs-rooted paths. The Builder
    resolves the affected attr's package directory inside the
    nixpkgs checkout (via the `pkgs/by-name/<aa>/<attr>/` convention,
    falling back to `nix eval` lookup) and passes
    `git apply --directory=<resolved>` so `a/package.nix` becomes
    `<resolved>/package.nix` at apply time.

    `git apply --check` runs first; only when the dry-run passes does
    the real apply commit the working-tree mutation. files_changed is
    extracted from the diff's `+++ b/...` headers.
    """
    diff_text = patch_diff_path.read_text()
    files_changed = _extract_changed_files(diff_text)

    package_dir_rel = _resolve_attr_package_dir(nixpkgs_checkout, attr)
    if package_dir_rel is None:
        return {
            "applied": False,
            "git_apply_exit_code": None,
            "files_changed": files_changed,
            "post_apply_sha": None,
            "reason": (
                f"could not resolve package directory for attr={attr!r} "
                f"inside the nixpkgs checkout. Tried pkgs/by-name/<aa>/<attr>/ "
                f"and nix eval --raw <checkout>#<attr>.meta.position; both "
                f"returned no result."
            ),
        }
    abs_dir = nixpkgs_checkout / package_dir_rel

    def _failed(reason: str, exit_code: int | None = None) -> dict[str, Any]:
        return {
            "applied": False,
            "git_apply_exit_code": exit_code,
            "files_changed": files_changed,
            "post_apply_sha": None,
            "reason": reason[:2048],
        }

    # Target-file resolution + canonical-filename remap (codex 2026-06-15). The
    # bundle always names the pre-patch file `package.nix`. For a by-name package the
    # real nixpkgs file IS package.nix. For a non-by-name multi-variant package the
    # real file differs (openssh: per-variant `openssh_gssapi = common rec {...}`
    # blocks live in default.nix, while meta.position points at the shared common.nix)
    # and must be found by CONTENT, not meta.position basename. When the target
    # basename != package.nix we remap the diff path headers onto it in a TEMP patch
    # (the committed patch.diff is never mutated). Bounded hard:
    #   * remap only a single-file canonical package.nix patch (git apply --numstat,
    #     which — unlike the `+++ b/`-only extractor — also sees deletions/renames),
    #   * candidates are *.nix regular files in the resolved dir only (no recursion),
    #   * primary signal = byte-match to the bundled package.nix; fallback = a unique
    #     git-apply --check hit; zero/ambiguous => refuse,
    #   * only diff path headers are rewritten, never hunk bodies.
    patch_to_apply = patch_diff_path
    remap_note: str | None = None
    cleanup_tmp: Path | None = None
    target_basename = "package.nix"
    # apply_mode: "by-name-package-nix" (a/package.nix + --directory),
    # "direct-package-dir" (full nixpkgs paths, repo root, no remap), or
    # "canonical-package-remap" (single-file package.nix -> real basename).
    apply_mode = "by-name-package-nix"
    direct_package_dir = False
    direct_changed: list[str] = []
    if not (abs_dir / "package.nix").is_file():
        # --recount so the path-extraction tolerates the SAME off-by-one hunk
        # counts the real apply tolerates (model-authored source-backport patches
        # routinely carry them); without it a valid patch would be rejected as
        # non-canonical before the --recount apply could succeed (codex 2026-06-15).
        numstat = subprocess.run(
            ["git", "apply", "--recount", "--numstat", str(patch_diff_path)],
            cwd=str(nixpkgs_checkout),
            check=False, capture_output=True, text=True,
        )
        numstat_paths = [
            ln.split("\t", 2)[2]
            for ln in numstat.stdout.splitlines()
            if ln.strip() and "\t" in ln
        ]
        # Direct repo-root apply for a non-by-name source-backport authored with
        # real nixpkgs paths fully contained in the package dir (codex 2026-06-15).
        # Such a patch touches >1 file (e.g. .../default.nix + .../CVE-XXXX.patch)
        # and is NOT a canonical one-file package.nix change, so the remap branch is
        # the wrong mode; but it already names real paths, so it applies at the repo
        # root with no remap and no --directory. Guardrails (codex): no
        # deletes/renames/symlinks; every path relative, normalized, no '..', and
        # contained in package_dir_rel; git apply --check must pass at the repo root.
        _unsafe_diff = any(
            marker in diff_text for marker in (
                "\ndeleted file mode ", "\nrename from ", "\nrename to ",
                "\nold mode ", "\nnew mode ", "120000",
            )
        )
        if (numstat.returncode == 0 and numstat_paths
                and not _unsafe_diff
                and _paths_contained_in(numstat_paths, package_dir_rel)):
            check_root = subprocess.run(
                ["git", "apply", "--recount", "--check", str(patch_diff_path)],
                cwd=str(nixpkgs_checkout),
                check=False, capture_output=True, text=True,
            )
            if check_root.returncode == 0:
                direct_package_dir = True
                direct_changed = numstat_paths
                apply_mode = "direct-package-dir"
        if not direct_package_dir:
            if numstat.returncode != 0 or numstat_paths != ["package.nix"]:
                return _failed(
                    f"attr {attr!r} resolves to dir {package_dir_rel!r} which has no "
                    f"package.nix; patch.diff is neither a single canonical "
                    f"package.nix change NOR a source-backport contained in the "
                    f"package dir (git apply --numstat paths={numstat_paths!r}, "
                    f"rc={numstat.returncode}, unsafe_diff={_unsafe_diff}); refusing "
                    f"to apply onto a non-by-name package"
                )
            sel_basename, method, reason = _select_remap_target(
                abs_dir=abs_dir,
                package_dir_rel=package_dir_rel,
                nixpkgs_checkout=nixpkgs_checkout,
                bundled_package_nix=patch_diff_path.parent / "package.nix",
                diff_text=diff_text,
            )
            if sel_basename is None:
                return _failed(reason)
            target_basename = sel_basename
            remapped = _remap_diff_basename(diff_text, "package.nix", target_basename)
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".diff", prefix="trace-remap-", delete=False
            )
            tmp.write(remapped)
            tmp.close()
            patch_to_apply = Path(tmp.name)
            cleanup_tmp = patch_to_apply
            remap_note = f"package.nix -> {package_dir_rel}/{target_basename} ({method})"
            apply_mode = "canonical-package-remap"

    # --recount: infer hunk line-counts from the patch body rather than trusting
    # the `@@ -a,b +c,d @@` headers. Model-authored patches (especially the
    # source-backport strategy, where the Patcher emits a new-file hunk
    # containing an embedded upstream diff) can carry an off-by-one count while
    # the actual +/- content and surrounding context are correct. --recount does
    # NOT relax content/context matching — git still requires the context lines
    # to match the target exactly — so it tolerates the model's arithmetic
    # without weakening the apply's correctness guarantee.
    # direct-package-dir patches carry real repo-root paths, so they apply WITHOUT
    # --directory (which would double-prefix the path); the other modes use a
    # bundle-relative path remapped under --directory.
    if direct_package_dir:
        apply_args = ["git", "apply", "--recount"]
    else:
        apply_args = ["git", "apply", "--recount", f"--directory={package_dir_rel}"]
    try:
        check = subprocess.run(
            [*apply_args, "--check", str(patch_to_apply)],
            cwd=str(nixpkgs_checkout),
            check=False, capture_output=True, text=True,
        )
        if check.returncode != 0:
            return _failed(
                f"git apply --check --directory={package_dir_rel} failed: "
                + (check.stderr or check.stdout or "(no stderr)"),
                exit_code=check.returncode,
            )
        real = subprocess.run(
            [*apply_args, str(patch_to_apply)],
            cwd=str(nixpkgs_checkout),
            check=False, capture_output=True, text=True,
        )
        if real.returncode != 0:
            return _failed(
                (real.stderr or real.stdout or "git apply failed"),
                exit_code=real.returncode,
            )
    finally:
        if cleanup_tmp is not None:
            cleanup_tmp.unlink(missing_ok=True)
    rev = _git_head_sha(nixpkgs_checkout)
    # Re-prefix files_changed with the resolved package directory so build.json's
    # record matches the actual nixpkgs-relative paths. When remapped, record the
    # REAL basename (default.nix), not the canonical package.nix.
    if direct_package_dir:
        # numstat paths are already full nixpkgs-relative paths; no re-prefix.
        files_changed_prefixed = direct_changed
    else:
        effective_changed = [target_basename] if remap_note else files_changed
        files_changed_prefixed = [
            f"{package_dir_rel}/{p}" for p in effective_changed
        ]
    result: dict[str, Any] = {
        "applied": True,
        "git_apply_exit_code": 0,
        "files_changed": files_changed_prefixed,
        "post_apply_sha": rev,
        "apply_mode": apply_mode,
    }
    if remap_note is not None:
        result["package_file_remap"] = remap_note
    return result


def _paths_contained_in(paths: list[str], package_dir_rel: str) -> bool:
    """True iff every git path is relative, normalized, free of '..', and lies
    inside `package_dir_rel` (the path-traversal guard for direct-package-dir
    apply, codex 2026-06-15). git emits forward-slash paths, so this is pure
    posix string logic — a path is contained iff it equals the dir or starts
    with `<dir>/`. Any absolute path, empty path, '..' segment, '.' segment, or
    backslash makes the whole patch ineligible for direct apply (it falls back
    to the canonical remap, which has its own guards, or is refused)."""
    prefix = package_dir_rel.rstrip("/") + "/"
    for p in paths:
        if not p or p.startswith("/") or "\\" in p:
            return False
        segs = p.split("/")
        if any(s in ("", ".", "..") for s in segs):
            return False
        if p != package_dir_rel and not p.startswith(prefix):
            return False
    return True


_ATTR_SAFE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$")


def _resolve_attr_package_file(
    nixpkgs_checkout: Path, attr: str | None,
) -> str | None:
    """Return the path of the package *file* for `attr` relative to
    `nixpkgs_checkout` (e.g. `pkgs/by-name/he/hello/package.nix` or, for a
    non-by-name multi-variant package, `pkgs/tools/networking/openssh/default.nix`),
    or None if it cannot be resolved.

    Tries in order:
      1. `pkgs/by-name/<aa>/<attr>/package.nix`        (current convention)
      2. `pkgs/by-name/<a>/<attr>/package.nix`         (single-char dir)
      3. `nix eval --raw <checkout>#<attr>.meta.position`  (flake ref, works
         for top-level attrs exposed by the nixpkgs flake)
      4. `nix eval --raw --impure --expr ...`           (legacy expression eval,
         works for nested sets such as rubyPackages.sinatra)

    Returns the full file path (with basename) of whichever resolution succeeds
    first; the basename distinguishes by-name (`package.nix`) from non-by-name
    multi-variant packages (`default.nix`), which the apply layer needs in order
    to remap the canonical bundle `package.nix` onto the real nixpkgs filename.
    """
    if not attr:
        return None
    aa = attr[:2].lower()
    candidates = [
        Path("pkgs") / "by-name" / aa / attr,
        Path("pkgs") / "by-name" / attr[:1].lower() / attr,
    ]
    for rel in candidates:
        if (nixpkgs_checkout / rel / "package.nix").is_file():
            return (str(rel) + "/package.nix").replace("\\", "/")

    # Guard: only pass attr through nix eval if it looks like a safe identifier
    # chain (alphanumeric + underscore, dot-separated). attr is the UNTRUSTED
    # field (sourced from resolver-input.json / the CVE feed); the regex
    # prevents nix-expression injection via a malformed attr_path.
    if not _ATTR_SAFE_RE.match(attr):
        return None

    checkout_abs = str(nixpkgs_checkout.resolve())
    # checkout_abs is TRUSTED operator/CI input (the nixpkgs checkout path),
    # never bundle-controlled — so a bare path literal is acceptable below.
    # Still reject newline/NUL defensively (keeps logs clean; NUL can't appear
    # in a real path anyway).
    if "\n" in checkout_abs or "\x00" in checkout_abs:
        return None

    def _position_from_proc(proc: subprocess.CompletedProcess[str]) -> str | None:
        if proc.returncode != 0:
            return None
        position = (proc.stdout or "").strip()
        file_path_str = position.rsplit(":", 1)[0]
        if not file_path_str:
            return None
        file_path = Path(file_path_str)
        try:
            rel = file_path.relative_to(nixpkgs_checkout.resolve())
        except ValueError:
            return None
        return str(rel).replace("\\", "/")

    # Attempts 3–5: resolve meta.position for legacy paths outside pkgs/by-name
    # (nested package sets like rubyPackages.*, python3Packages.*).
    #
    # nix-instantiate uses a bare path literal (no builtins.path) because
    # builtins.path copies the nixpkgs tree into the store, which is slow and
    # requires store write access. The bare literal is added to the store
    # lazily at import time, which works in both local and CI environments.
    # nix eval --impure --expr uses builtins.path for correct quoting because
    # the newer nix CLI is stricter about bare path interpolation in expressions.
    bare_expr = f"(import {checkout_abs} {{}}).{attr}.meta.position"
    checkout_json = json.dumps(checkout_abs)
    quoted_expr = (
        f"(import (builtins.path {{ path = {checkout_json}; name = \"nixpkgs\"; }}) "
        f"{{}}).{attr}.meta.position"
    )

    # Attempt 3: nix-instantiate (classic interface; no nix-command feature flag).
    try:
        proc = subprocess.run(
            ["nix-instantiate", "--eval", "--raw", "--expr", bare_expr],
            check=False, capture_output=True, text=True, timeout=60,
        )
        result = _position_from_proc(proc)
        if result is not None:
            return result
    except (OSError, subprocess.SubprocessError):
        pass

    # Attempt 4: nix eval flake ref — works when <attr> is a top-level nixpkgs
    # flake output (e.g. some top-level attrs before pkgs/by-name migration).
    try:
        proc = subprocess.run(
            ["nix", "eval", "--raw", f"{checkout_abs}#{attr}.meta.position"],
            check=False, capture_output=True, text=True, timeout=60,
        )
        result = _position_from_proc(proc)
        if result is not None:
            return result
    except (OSError, subprocess.SubprocessError):
        pass

    # Attempt 5: nix eval --impure --expr (requires nix-command feature flag).
    try:
        proc = subprocess.run(
            ["nix", "eval", "--raw", "--impure", "--expr", quoted_expr],
            check=False, capture_output=True, text=True, timeout=60,
        )
        return _position_from_proc(proc)
    except (OSError, subprocess.SubprocessError):
        return None


def _resolve_attr_package_dir(
    nixpkgs_checkout: Path, attr: str | None,
) -> str | None:
    """Directory portion of `_resolve_attr_package_file` (kept for callers/tests
    that only need the package directory, not the filename)."""
    f = _resolve_attr_package_file(nixpkgs_checkout, attr)
    if f is None:
        return None
    return f.rsplit("/", 1)[0] if "/" in f else f


def _remap_diff_basename(diff_text: str, old: str, new: str) -> str:
    """Rewrite ONLY the git unified-diff path headers for a single file from
    `old` to `new` basename, leaving hunk bodies (and everything else) untouched.

    Used by the apply layer to map the canonical bundle filename (`package.nix`)
    onto the real nixpkgs file (`default.nix`) for non-by-name multi-variant
    packages. Touches exactly the three header forms git apply reads for the
    target path: `diff --git a/<f> b/<f>`, `--- a/<f>`, `+++ b/<f>`. Never edits
    `+`/`-`/context/`@@` lines — so the patch content is provably unchanged.
    """
    out: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped == f"diff --git a/{old} b/{old}":
            out.append(f"diff --git a/{new} b/{new}\n")
        elif stripped == f"--- a/{old}":
            out.append(f"--- a/{new}\n")
        elif stripped == f"+++ b/{old}":
            out.append(f"+++ b/{new}\n")
        else:
            out.append(line)
    return "".join(out)


def _select_remap_target(
    *,
    abs_dir: Path,
    package_dir_rel: str,
    nixpkgs_checkout: Path,
    bundled_package_nix: Path,
    diff_text: str,
) -> tuple[str | None, str | None, str]:
    """Pick the real nixpkgs file basename a canonical `package.nix` patch targets,
    for a non-by-name package whose dir has no `package.nix`. Returns
    `(basename, method, "")` on success or `(None, None, reason)` on refusal.

    Bounded (codex 2026-06-15): candidates are `*.nix` REGULAR files (no symlinks,
    no recursion) in `abs_dir` that resolve inside the checkout. Primary signal is a
    byte-for-byte match to the bundle's shipped `package.nix` (proves the pre-image
    was copied from that exact file); fallback is a UNIQUE `git apply --check` hit
    among candidates. Zero or multiple matches at either stage => refuse.
    """
    root = nixpkgs_checkout.resolve()
    candidates = []
    for p in sorted(abs_dir.glob("*.nix")):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            p.resolve().relative_to(root)
        except ValueError:
            continue
        candidates.append(p)
    if not candidates:
        return None, None, f"no in-checkout *.nix candidates in {package_dir_rel} to remap onto"

    # Primary: exact byte-match to the bundled package.nix.
    if bundled_package_nix.is_file():
        want = bundled_package_nix.read_bytes()
        matches = [p for p in candidates if p.read_bytes() == want]
        if len(matches) == 1:
            return matches[0].name, "content-match", ""
        if len(matches) > 1:
            return None, None, (
                f"ambiguous content-match ({len(matches)} *.nix files byte-equal to the "
                f"bundled package.nix) in {package_dir_rel}; refusing to remap"
            )

    # Fallback: a single git-apply --check hit among candidates.
    applies: list[str] = []
    for p in candidates:
        remapped = _remap_diff_basename(diff_text, "package.nix", p.name)
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".diff", prefix="trace-probe-", delete=False
        )
        try:
            tmp.write(remapped)
            tmp.close()
            chk = subprocess.run(
                ["git", "apply", "--recount", "--check",
                 f"--directory={package_dir_rel}", tmp.name],
                cwd=str(nixpkgs_checkout),
                check=False, capture_output=True, text=True,
            )
            if chk.returncode == 0:
                applies.append(p.name)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
    if len(applies) == 1:
        return applies[0], "apply-check", ""
    if len(applies) > 1:
        return None, None, (
            f"ambiguous apply-check ({len(applies)} *.nix files accept the patch) in "
            f"{package_dir_rel}; refusing to remap"
        )
    return None, None, (
        f"no *.nix file in {package_dir_rel} matches the canonical package.nix patch "
        f"(neither byte-match to the bundled package.nix nor a git-apply --check hit)"
    )


def _patch_apply_skipped(reason: str) -> dict[str, Any]:
    return {
        "applied": False,
        "git_apply_exit_code": None,
        "files_changed": [],
        "post_apply_sha": None,
        "reason": reason,
    }


def _refused_result(
    *,
    cve_id: str,
    bundle_id: str,
    nixpkgs_rev: str,
    host: dict[str, str],
    started_at: str,
    patch_apply: dict[str, Any],
    dispatch_outcome: str,
    instrumentation: str | None = None,
) -> BuilderRunResult:
    skipped_phase = {
        "applied": False,
        "outcome": "skipped",
        "exit_code": None,
        "drv_path": None,
        "out_path": None,
        "elapsed_seconds": None,
        "stdout_stderr": "",
        "stdout_stderr_log_sha256": None,
        "reason": "patch-or-reproducer-missing",
    }
    build_json = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "bundle_id": bundle_id,
        "nixpkgs_rev": nixpkgs_rev,
        "builder_id": BUILDER_ID,
        "host": dict(host),
        "started_at": started_at,
        "ended_at": _utc_now_iso(),
        "patch_apply": patch_apply,
        "patched_build": skipped_phase,
        "unpatched": dict(skipped_phase),
        "patched": dict(skipped_phase),
        "passthru_tests_ground_truth": [],
        "sbom_delta_attempted": False,
        "dispatch_outcome": dispatch_outcome,
        "instrumentation": instrumentation,
    }
    return BuilderRunResult(
        build_json=build_json, dispatch_outcome=dispatch_outcome,
    )


def _patch_apply_failed_result(
    *,
    cve_id: str,
    bundle_id: str,
    nixpkgs_rev: str,
    host: dict[str, str],
    started_at: str,
    patch_apply: dict[str, Any],
    unpatched_phase: dict[str, Any] | None = None,
    unpatched_full: str = "",
    instrumentation: str | None = None,
) -> BuilderRunResult:
    """Return a patch-apply-failed result.

    `unpatched_phase` is the §2.2a unpatched reproducer block (pre-patch
    tree), which runs BEFORE patch-apply. When patch-apply subsequently
    fails, the unpatched block is still meaningful evidence and is
    preserved in build.json. When the caller didn't compute one (e.g.,
    no reproducer present), pass None to record a `skipped` block.
    """
    skipped_phase = {
        "applied": False,
        "outcome": "skipped",
        "exit_code": None,
        "drv_path": None,
        "out_path": None,
        "elapsed_seconds": None,
        "stdout_stderr": "",
        "stdout_stderr_log_sha256": None,
        "reason": "patch-apply-failed",
    }
    full_logs: dict[str, str] = {
        "patched_build": "", "unpatched": unpatched_full, "patched": "",
    }
    build_json = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "bundle_id": bundle_id,
        "nixpkgs_rev": nixpkgs_rev,
        "builder_id": BUILDER_ID,
        "host": dict(host),
        "started_at": started_at,
        "ended_at": _utc_now_iso(),
        "patch_apply": patch_apply,
        "patched_build": dict(skipped_phase),
        "unpatched": unpatched_phase if unpatched_phase is not None else dict(skipped_phase),
        "patched": dict(skipped_phase),
        "passthru_tests_ground_truth": [],
        "sbom_delta_attempted": False,
        "dispatch_outcome": "patch-apply-failed",
        "instrumentation": instrumentation,
    }
    return BuilderRunResult(
        build_json=build_json, dispatch_outcome="patch-apply-failed",
        full_logs=full_logs,
    )


def _instrumentation_malformed_result(
    *,
    cve_id: str,
    bundle_id: str,
    nixpkgs_rev: str,
    host: dict[str, str],
    started_at: str,
    reason: str,
) -> BuilderRunResult:
    """Builder refusal: reproducer-instrumentation.json is present but
    doesn't validate. Per the slice contract, this is a structured
    refusal, NOT a silent fallback to no-instrumentation."""
    skipped_phase = {
        "applied": False,
        "outcome": "skipped",
        "exit_code": None,
        "drv_path": None,
        "out_path": None,
        "elapsed_seconds": None,
        "stdout_stderr": "",
        "stdout_stderr_log_sha256": None,
        "reason": "instrumentation-malformed",
    }
    patch_apply = {
        "applied": False,
        "git_apply_exit_code": None,
        "files_changed": [],
        "post_apply_sha": None,
        "reason": reason[:2048],
    }
    build_json = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "bundle_id": bundle_id,
        "nixpkgs_rev": nixpkgs_rev,
        "builder_id": BUILDER_ID,
        "host": dict(host),
        "started_at": started_at,
        "ended_at": _utc_now_iso(),
        "patch_apply": patch_apply,
        "patched_build": dict(skipped_phase),
        "unpatched": dict(skipped_phase),
        "patched": dict(skipped_phase),
        "passthru_tests_ground_truth": [],
        "sbom_delta_attempted": False,
        "dispatch_outcome": "instrumentation-malformed",
        "instrumentation": None,
    }
    return BuilderRunResult(
        build_json=build_json,
        dispatch_outcome="instrumentation-malformed",
    )


def _read_instrumentation(
    path: Path,
) -> tuple[str | None, bool, str | None]:
    """Read + validate reproducer-instrumentation.json.

    Returns (instrumentation, disable_doCheck, error) where:
      * instrumentation is None when the file is absent OR when the file
        exists, parses, and `asan: false` (explicit opt-out is the same
        as absent for the rest of the pipeline)
      * instrumentation is "asan" when the file validates with `asan: true`
      * disable_doCheck is True iff the file declares `disable_doCheck: true`;
        False otherwise (absent file, absent key, or explicit false)
      * error is a human-readable diagnostic when the file is present but
        malformed (invalid JSON, wrong schema_version, asan/disable_doCheck
        not a bool, unknown extra keys). The caller turns this into a
        structured instrumentation-malformed refusal.

    Both knobs are independent: a bundle may declare asan=true without
    disable_doCheck, or vice versa, or both, or neither. asan=false +
    disable_doCheck=true is the typical libtiff-class shape; asan=true +
    disable_doCheck=false is the mruby shape.
    """
    if not path.is_file():
        return None, False, None
    try:
        body = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return None, False, f"reproducer-instrumentation.json: not valid JSON: {exc}"
    if not isinstance(body, dict):
        return None, False, (
            "reproducer-instrumentation.json: top-level must be a JSON "
            f"object, got {type(body).__name__}"
        )
    allowed_keys = {"schema_version", "asan", "disable_doCheck"}
    extra = set(body.keys()) - allowed_keys
    if extra:
        return None, False, (
            f"reproducer-instrumentation.json: unknown keys "
            f"{sorted(extra)!r}; v0 only accepts {sorted(allowed_keys)!r}"
        )
    schema_version = body.get("schema_version")
    if schema_version != "1.0.0":
        return None, False, (
            f"reproducer-instrumentation.json: schema_version must be "
            f"\"1.0.0\", got {schema_version!r}"
        )
    # `asan` is the only required-when-present knob retained as required for
    # backwards compat with v0.1 of the schema; absence is treated as false.
    asan = body.get("asan", False)
    if not isinstance(asan, bool):
        return None, False, (
            "reproducer-instrumentation.json: `asan` must be a boolean, "
            f"got {type(asan).__name__}"
        )
    disable_doCheck_raw = body.get("disable_doCheck", False)
    if not isinstance(disable_doCheck_raw, bool):
        return None, False, (
            "reproducer-instrumentation.json: `disable_doCheck` must be a "
            f"boolean, got {type(disable_doCheck_raw).__name__}"
        )
    return (
        "asan" if asan else None,
        disable_doCheck_raw,
        None,
    )


# ─── §2.4: passthru enumeration ──────────────────────────────────────────


def _enumerate_passthru_tests(
    *,
    build_runner: BuildRunner,
    attr: str,
    cwd: Path,
    timeout_seconds: int,
) -> list[dict[str, Any]]:
    """Enumerate `<pkgs>.<attr>.passthru.tests` plus related nixosTests.

    v0 implementation: single `nix-build` of a small Nix expression
    that returns a JSON array. We use `nix-build -E` rather than
    `nix eval` to keep the dependency surface minimal — the same
    BuildRunner that handles the patched-build handles this too.

    The expression evaluates passthru.tests as `lib.attrNames` and
    nixosTests filtered to those whose name contains `attr`. Returns
    a list of `{name, drv_path, kind}` entries; v0 leaves drv_path as
    null because nix-build's stdout doesn't expose it for set-shaped
    outputs in a stable way (a future Builder iteration can fold this
    in via `nix eval --json`).
    """
    expr = (
        "let "
        "pkgs = import ./. { config.allowUnsupportedSystem = true; }; "
        f"attrPath = \"{attr}\"; "
        "passthru = pkgs.${attrPath}.passthru.tests or { }; "
        "passthruNames = builtins.attrNames passthru; "
        "nixosTests = pkgs.nixosTests or { }; "
        "matchingNixos = builtins.filter "
        "  (n: builtins.match (\".*${attrPath}.*\") n != null) "
        "  (builtins.attrNames nixosTests); "
        "manifest = "
        "  (builtins.map (n: { name = \"passthru.tests.\" + n; kind = \"passthru.tests\"; }) passthruNames) "
        "  ++ (builtins.map (n: { name = \"nixosTests.\" + n; kind = \"nixosTests\"; }) matchingNixos); "
        "in pkgs.writeText \"manifest.json\" (builtins.toJSON manifest)"
    )
    outcome = build_runner.run(
        nix_expression=expr,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )
    if outcome.exit_code != 0 or not outcome.out_path:
        return []
    try:
        manifest_path = Path(outcome.out_path)
        if not manifest_path.is_file():
            return []
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(manifest, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in manifest:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        kind = entry.get("kind")
        if isinstance(name, str) and kind in ("passthru.tests", "nixosTests"):
            out.append({"name": name, "drv_path": None, "kind": kind})
    return out


# ─── reproducer expression generation ────────────────────────────────────


def _no_check_expression(attr: str) -> str:
    """Build a Nix expression that selects `attr` from default.nix with
    doCheck=false overridden in. Used for the patched-build sanity phase
    when reproducer-instrumentation.json sets disable_doCheck=true.

    Form:
      `((import ./. { config.allowUnsupportedSystem = true; }).<attr>.overrideAttrs (old: { doCheck = false; }))`

    The cwd is the nixpkgs checkout; `import ./.` loads the top-level
    package set. Equivalent to `nix-build -A <attr>` followed by
    `.overrideAttrs (..)` — Builder takes the expression path because
    nix-build's `-A` doesn't compose with overrideAttrs at the CLI.
    """
    return (
        "((import ./. { config.allowUnsupportedSystem = true; })."
        + attr
        + ".overrideAttrs (old: { doCheck = false; }))"
    )


def _repro_nix_expression(
    reproducer_nix_path: Path,
    *,
    attr_in_repro: str,
    nixpkgs_pin: Path | None = None,
) -> str:
    """Build a Nix expression that imports reproducer.nix and selects an attr.

    v0 form: `((import <abs-path> {}).<attr>)`. Builder runs nix-build
    against this expression; the BuildRunner captures stdout/stderr,
    which is what the reproducer scorers grep for SIGNAL_UNPATCHED /
    SIGNAL_PATCHED substrings.

    When `nixpkgs_pin` is provided, reproducer.nix is invoked with
    `pkgs = import <nixpkgs-pin> {}` overriding the default
    `pkgs ? import <nixpkgs> {}`. This ensures `pkgs.<attr>` references
    inside reproducer.nix resolve against the bundle's pinned nixpkgs
    tree (with any patch-apply state in effect), not the system's
    NIX_PATH-resolved default. Without this pin, reproducer-side
    behaviour drifts on hosts where the system nixpkgs has moved past
    the bundle's rev.
    """
    abs_path = str(reproducer_nix_path.resolve())
    if nixpkgs_pin is not None:
        pin_abs = str(nixpkgs_pin.resolve())
        return (
            f"((import {abs_path} {{ pkgs = import {pin_abs} {{}}; }})"
            f".{attr_in_repro})"
        )
    return f"((import {abs_path} {{}}).{attr_in_repro})"


# ─── small utilities ─────────────────────────────────────────────────────


def _read_json(p: Path) -> dict[str, Any] | None:
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _git_head_sha(cwd: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd), check=False, capture_output=True, text=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _extract_changed_files(diff_text: str) -> list[str]:
    """Parse `+++ b/<path>` headers from a unified diff."""
    files: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            files.append(line[len("+++ b/"):].strip())
        elif line.startswith("+++ "):
            tail = line[4:].strip()
            if tail and tail != "/dev/null":
                # already normalised (no leading "b/")
                files.append(tail)
    return files


def _default_host_info() -> dict[str, str]:
    """Used by tests when the executor does not supply host_info."""
    return {
        "system": "x86_64-linux",
        "nix_version": "unknown",
        "tool_version": "trace-cli/0.0.0",
    }


__all__ = [
    "BUILDER_ID",
    "BuilderRunResult",
    "SCHEMA_VERSION",
    "run_builder",
]
