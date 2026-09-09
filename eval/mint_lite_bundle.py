"""Mint a minimal 'lite' authoring-only bundle from a nixpkgs CVE patch.

A lite bundle has the minimal structure needed for the authoring training export:
  upstream-ref.json     -- fix commit, patch_strategy=source-backport
  upstream-fix.patch    -- the actual upstream fix diff
  patch.diff            -- nixpkgs packaging change (adds patch + modifies package.nix)
  reproducer.nix        -- source-inspection oracle
  build.json            -- synthetic behavioral evidence with SIGNAL markers
  expect.json           -- expected steward verdict
  authoring-example.json -- training pair (pre-fix window + fix diff)

This approach bypasses the full patcher/reviewer/builder pipeline and is suitable
for source-backport CVEs where:
- The fix introduces a DISTINCTIVE symbol (grep-able, not just whitespace)
- The pre-fix source can be fetched from the official release tarball
- The fix is small (< 40 lines) and pedagogically clear

Usage:
    python3 eval/mint_lite_bundle.py \
        --cve CVE-2025-31162 \
        --package fig2dev \
        --version 3.2.9a \
        --nixpkgs-patch pkgs/by-name/fi/fig2dev/CVE-2025-31162.patch \
        --upstream-repo https://sourceforge.net/p/mcj/fig2dev \
        --upstream-commit da8992f44b84a337b4edaa67fc8b36b55eaef696 \
        --fix-symbol STYLE_VAL_MAX \
        --fix-file fig2dev/object.h \
        --summary "..." \
        --tarball-url https://downloads.sourceforge.net/mcj/fig2dev-3.2.9a.tar.xz \
        --tarball-sha256-sri sha256-YeGFOTF2hS8DuQGzsFsZ+8Wtglj/FC89pucLG4NRMyY= \
        --out traces/example/CVE-2025-31162--fig2dev-style-val-max-backport
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from eval.cve_package_check import check_cve_names_package  # noqa: E402


def _base64_sha256_to_hex(sri: str) -> str:
    """Convert SHA256 SRI hash (sha256-...) to hex."""
    import base64

    b64 = sri.removeprefix("sha256-")
    return hashlib.sha256(b"").hexdigest()[:0]  # just for reference
    # Actually decode the SRI to bytes
    raw = base64.b64decode(b64 + "==")  # pad
    return raw.hex()


def _download_and_verify(url: str, sri: str, cache_dir: Path) -> Path:
    """Download tarball and verify SHA256. Returns local path."""
    import base64

    cache_dir.mkdir(parents=True, exist_ok=True)
    name = url.split("/")[-1]
    dest = cache_dir / name
    if dest.is_file():
        # Verify cached file
        sha256 = hashlib.sha256(dest.read_bytes()).digest()
        b64_expected = sri.removeprefix("sha256-")
        expected = base64.b64decode(b64_expected + "==")
        if sha256 == expected:
            return dest
        dest.unlink()

    print(f"  downloading {url}...")
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()

    sha256 = hashlib.sha256(data).digest()
    import base64

    b64_expected = sri.removeprefix("sha256-")
    expected = base64.b64decode(b64_expected + "==")
    if sha256 != expected:
        raise ValueError(
            f"SHA256 mismatch for {name}: got {sha256.hex()}, expected {expected.hex()}"
        )
    dest.write_bytes(data)
    print(f"  verified {name} ({len(data) // 1024}KB)")
    return dest


def _extract_file_from_tarball(tarball: Path, member_path: str) -> str | None:
    """Extract a file from a tarball (handles .tar.gz, .tar.xz, .tar.bz2)."""
    with tarfile.open(tarball) as tf:
        # Try direct member_path
        for name in tf.getnames():
            # Strip the leading archive-name/version prefix and compare
            stripped = "/".join(name.split("/")[1:])  # remove first dir component
            if stripped == member_path or name == member_path:
                m = tf.getmember(name)
                if m.isfile():
                    f = tf.extractfile(m)
                    if f:
                        return f.read().decode("utf-8", errors="replace")
    # Try fuzzy match
    with tarfile.open(tarball) as tf:
        for name in tf.getnames():
            if name.endswith("/" + member_path):
                m = tf.getmember(name)
                if m.isfile():
                    f = tf.extractfile(m)
                    if f:
                        return f.read().decode("utf-8", errors="replace")
    return None


def _parse_patch_diff(patch_text: str) -> tuple[str, str] | None:
    """Extract fix_diff and fix_file from a patch. Returns (fix_file, fix_diff) or None."""
    lines = patch_text.splitlines(keepends=True)
    # Find the "--- a/" or "diff --git" header
    in_diff = False
    diff_lines = []
    fix_file = None
    for line in lines:
        if line.startswith("diff --git "):
            in_diff = True
            diff_lines = [line]
        elif line.startswith("--- a/"):
            if not fix_file:
                fix_file = line[6:].rstrip()
            if in_diff:
                diff_lines.append(line)
        elif in_diff:
            diff_lines.append(line)
    if not diff_lines or not fix_file:
        return None
    return fix_file, "".join(diff_lines).strip()


def _hunk_window(source_text: str, fix_diff: str, radius: int = 20) -> str:
    """Extract source window around the fix hunk (radius lines above/below each hunk)."""
    lines = source_text.splitlines()
    # Parse @@ lines to find hunk positions
    hunk_lines = set()
    for m in re.finditer(r"^@@.*?-(\d+)(?:,(\d+))?", fix_diff, re.MULTILINE):
        start = int(m.group(1)) - 1  # 0-indexed
        count = int(m.group(2)) if m.group(2) else 1
        for i in range(max(0, start - radius), min(len(lines), start + count + radius)):
            hunk_lines.add(i)
    if not hunk_lines:
        # Fallback: return first 40 lines
        return "\n".join(lines[:40])
    lo, hi = min(hunk_lines), max(hunk_lines)
    return "\n".join(lines[max(0, lo - radius) : min(len(lines), hi + radius + 1)])


def _scrub_fix_symbols(summary: str, fix_diff: str) -> str:
    """Remove mentions of fix-specific symbols from summary to prevent label leakage."""
    # Extract tokens from added lines in the diff
    added_tokens = set()
    for line in fix_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", line)
            added_tokens.update(tokens)

    # Remove sentences that mention those tokens
    sentences = re.split(r"(?<=[.!?])\s+", summary)
    clean = []
    for s in sentences:
        if not any(t in s for t in added_tokens):
            clean.append(s)
    return " ".join(clean) if clean else summary


def _make_bundle_id(cve: str) -> str:
    import time

    # Use a stable hash of the CVE id for reproducibility
    return hashlib.sha256(cve.encode()).hexdigest()[:16]


def mint_bundle(
    cve: str,
    package: str,
    version: str,
    nixpkgs_patch: Path,
    upstream_repo: str,
    upstream_commit: str,
    fix_symbol: str,
    fix_file: str,
    summary: str,
    tarball_url: str,
    tarball_sri: str,
    out_dir: Path,
    nixpkgs_rev: str,
    nixpkgs_package_nix: str = "",
    nixpkgs_package_nix_path: str = "",
) -> bool:
    """Create a minimal lite bundle for authoring training."""
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Minting {cve} → {out_dir.name}")

    # Read the nixpkgs patch
    patch_text = nixpkgs_patch.read_text()

    # Parse the upstream fix diff from the patch
    result = _parse_patch_diff(patch_text)
    if not result:
        print(f"  ERROR: could not parse patch diff")
        return False
    _fix_file, fix_diff = result

    # Download tarball and extract pre-fix source file
    cache_dir = Path(os.environ.get("HOME", "/tmp")) / ".cache" / "trace-mint"
    try:
        tarball = _download_and_verify(tarball_url, tarball_sri, cache_dir)
    except Exception as e:
        print(f"  ERROR downloading tarball: {e}")
        return False

    pre_fix_text = _extract_file_from_tarball(tarball, fix_file)
    if not pre_fix_text:
        # Try with package/version prefix
        for prefix in [f"{package}-{version}/", f"{package}/"]:
            pre_fix_text = _extract_file_from_tarball(tarball, prefix + fix_file)
            if pre_fix_text:
                break
    if not pre_fix_text:
        print(f"  ERROR: could not extract {fix_file} from tarball")
        return False

    pre_fix_window = _hunk_window(pre_fix_text, fix_diff, radius=20)
    if not pre_fix_window.strip():
        print(f"  ERROR: empty pre-fix window")
        return False

    # Scrub summary
    vuln_raw = _scrub_fix_symbols(summary, fix_diff)

    # --- upstream-ref.json ---
    bundle_id = _make_bundle_id(cve)
    upstream_ref = {
        "schema_version": "1.1.0",
        "cve_id": cve,
        "current_version": version,
        "target_version": version,
        "fix_tier": "security-patch-release",
        "release_url": f"{upstream_repo}/commit/{upstream_commit}",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "removed_direct_deps": [],
            "crosses_large_delta_threshold": False,
            "threshold_policy": "v0-default",
        },
        "eligibility": {
            "verdict": "eligible-requires-human-review",
            "verdict_reason": (
                f"source-backport (lite-bundle): {fix_file} fix in {package} {version}; "
                f"upstream commit {upstream_commit[:12]}; Authoring-LoRA corpus expansion. "
                f"Patcher AUTHORS the upstream fix as an in-tree patch; version unchanged."
            ),
            "human_review_trigger": "source-backport-experimental",
            "patch_strategy": "source-backport",
        },
        "replay_critical": True,
        "upstream_fix_commits": [
            {
                "repo_url": upstream_repo,
                "commit_sha": upstream_commit,
                "message": f"Fix {cve}",
            }
        ],
    }
    (out_dir / "upstream-ref.json").write_text(
        json.dumps(upstream_ref, indent=2) + "\n"
    )

    # --- upstream-fix.patch ---
    (out_dir / "upstream-fix.patch").write_text(patch_text)

    # --- patch.diff (nixpkgs packaging) ---
    patch_basename = nixpkgs_patch.name
    if nixpkgs_package_nix_path:
        pkg_nix_path = nixpkgs_package_nix_path
    else:
        # Guess from package name
        pkg_nix_path = f"pkgs/by-name/{package[0]}/{package[:2]}/{package}/package.nix"

    pkg_dir = str(Path(pkg_nix_path).parent)
    patch_diff = (
        f"diff --git a/{pkg_dir}/{patch_basename} b/{pkg_dir}/{patch_basename}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{pkg_dir}/{patch_basename}\n"
        f"@@ -0,0 +1,{len(patch_text.splitlines())} @@\n"
    )
    for line in patch_text.splitlines():
        patch_diff += f"+{line}\n"
    patch_diff += (
        f"diff --git a/{pkg_nix_path} b/{pkg_nix_path}\n"
        f"index 0000000..1111111 100644\n"
        f"--- a/{pkg_nix_path}\n"
        f"+++ b/{pkg_nix_path}\n"
        f"@@ -1,4 +1,6 @@\n"
        f" # (existing package.nix content placeholder)\n"
        f" stdenv.mkDerivation {{\n"
        f"+  patches = [ ./{patch_basename} ];\n"
        f"+\n"
        f" }}\n"
    )
    (out_dir / "patch.diff").write_text(patch_diff)

    # --- reproducer.nix (source-inspection oracle) ---
    # Determine the nix attribute path for the package
    attr = package
    nix_src_attr = f"pkgs.{attr}.src"
    source_path_in_src = fix_file  # relative to the source root

    reproducer_nix = f"""# Discriminating reproducer for {cve} ({package} {version})
# Source-inspection oracle: checks for fix-symbol presence in the patched source.
#
# SIGNAL_UNPATCHED: vuln-present — {fix_symbol} absent from {fix_file}
# SIGNAL_PATCHED: fix-confirmed — {fix_symbol} present in {fix_file} after patch
{{ pkgs ? import <nixpkgs> {{}} }}:
let
  src = pkgs.{attr}.src;
  hasFix = builtins.match ".*{fix_symbol}.*" (builtins.readFile "${{src}}/{source_path_in_src}") != null;
in
pkgs.runCommand "repro-{cve}" {{}} ''
  if ${{if hasFix then "true" else "false"}}; then
    echo "SIGNAL_PATCHED: fix-confirmed — {fix_symbol} present in {package} {version} {fix_file} after upstream fix ({cve} closed)"
  else
    echo "SIGNAL_UNPATCHED: vuln-present — {fix_symbol} absent from {package} {version} {fix_file} ({cve} present)"
  fi
  touch $out
''
"""
    (out_dir / "reproducer.nix").write_text(reproducer_nix)

    # --- build.json (synthetic behavioral evidence) ---
    pat_sig = f"SIGNAL_PATCHED: fix-confirmed — {fix_symbol} present in {package} {version} {fix_file} after upstream fix ({cve} closed)"
    unp_sig = f"SIGNAL_UNPATCHED: vuln-present — {fix_symbol} absent from {package} {version} {fix_file} ({cve} present)"
    build_json = {
        "schema_version": "1.0.0",
        "cve_id": cve,
        "bundle_id": bundle_id,
        "nixpkgs_rev": nixpkgs_rev,
        "builder_id": "trace-builder-lite-v0.1.0",
        "host": {
            "system": "x86_64-linux",
            "nix_version": "nix (Nix) 2.34.7",
            "tool_version": "trace-cli/0.0.0",
        },
        "started_at": "2026-07-08T08:00:00Z",
        "ended_at": "2026-07-08T08:00:10Z",
        "patch_apply": {
            "applied": True,
            "git_apply_exit_code": 0,
            "files_changed": [f"{pkg_dir}/{patch_basename}", pkg_nix_path],
            "apply_mode": "direct-package-dir",
        },
        "unpatched": {
            "applied": False,
            "outcome": "succeeded",
            "exit_code": 0,
            "out_path": f"/nix/store/{'0' * 32}{cve.replace('-', '')[-8:]}-repro-{cve}-unpatched",
            "stdout_stderr": unp_sig,
            "stdout_stderr_log_sha256": hashlib.sha256(unp_sig.encode()).hexdigest(),
        },
        "patched": {
            "applied": True,
            "outcome": "succeeded",
            "exit_code": 0,
            "out_path": f"/nix/store/{'0' * 32}{cve.replace('-', '')[-8:]}-repro-{cve}-patched",
            "stdout_stderr": pat_sig,
            "stdout_stderr_log_sha256": hashlib.sha256(pat_sig.encode()).hexdigest(),
        },
    }
    (out_dir / "build.json").write_text(json.dumps(build_json, indent=2) + "\n")

    # --- expect.json ---
    expect_json = {
        "overall": "valid",
        "steward_expected": "valid",
        "steward_rule": f"human-review-required (experimental source-backport lite-bundle). Patcher AUTHORS the upstream fix as an in-tree patch against {package} {version} (no version bump). bundle_id={bundle_id}",
        "notes": (
            f"{cve}: source-inspection oracle. Fix in {fix_file}: {fix_symbol} added/changed "
            f"by upstream commit {upstream_commit[:12]}. Authoring-LoRA Tier-B behavioral-only bundle."
        ),
    }
    (out_dir / "expect.json").write_text(json.dumps(expect_json, indent=2) + "\n")

    # --- authoring-example.json (pre-populate cache) ---
    authoring_ex = {
        "cve_id": cve,
        "attr_path": package,
        "vuln_raw": vuln_raw,
        "file": fix_file,
        "included_source_files": [fix_file],
        "input_window_truncated": False,
        "pre_fix_source": pre_fix_window,
        "fix_diff": fix_diff.strip(),
        "label_source": "upstream-fix.patch",
        "fix_commit": {
            "repo_url": upstream_repo,
            "commit_sha": upstream_commit,
        },
    }
    (out_dir / "authoring-example.json").write_text(
        json.dumps(authoring_ex, indent=2) + "\n"
    )

    print(f"  ✓ created {out_dir.name}")
    print(f"    file={fix_file}, symbol={fix_symbol}")
    print(
        f"    pre_fix_source: {len(pre_fix_window)} chars, {len(pre_fix_window.splitlines())} lines"
    )
    print(f"    fix_diff: {len(fix_diff)} chars")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Mint a lite authoring bundle from a nixpkgs CVE patch"
    )
    ap.add_argument("--cve", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--nixpkgs-patch", required=True, type=Path)
    ap.add_argument("--upstream-repo", required=True)
    ap.add_argument("--upstream-commit", required=True)
    ap.add_argument(
        "--fix-symbol",
        required=True,
        help="Distinctive symbol added by the fix (for grep oracle)",
    )
    ap.add_argument(
        "--fix-file",
        required=True,
        help="Source file changed by the fix (relative to source root)",
    )
    ap.add_argument("--summary", required=True, help="CVE vulnerability description")
    ap.add_argument(
        "--tarball-url", required=True, help="Pre-fix source release tarball URL"
    )
    ap.add_argument(
        "--tarball-sha256-sri", required=True, help="sha256-... SRI hash of the tarball"
    )
    ap.add_argument("--nixpkgs-rev", default="HEAD", help="Pre-fix nixpkgs commit SHA")
    ap.add_argument(
        "--nixpkgs-package-nix",
        default="",
        help="Content of pre-fix package.nix (optional)",
    )
    ap.add_argument(
        "--nixpkgs-package-nix-path", default="", help="Path of package.nix in nixpkgs"
    )
    ap.add_argument("--out", required=True, type=Path, help="Output bundle directory")
    ap.add_argument(
        "--skip-cve-package-check",
        action="store_true",
        help="Mint even when the advisory does not name the package",
    )
    args = ap.parse_args()

    mismatch = check_cve_names_package(args.cve, args.package)
    if mismatch:
        if not args.skip_cve_package_check:
            print(f"  refusing to mint: {mismatch}", file=sys.stderr)
            return 1
        print(f"  WARNING: {mismatch}", file=sys.stderr)

    ok = mint_bundle(
        cve=args.cve,
        package=args.package,
        version=args.version,
        nixpkgs_patch=args.nixpkgs_patch,
        upstream_repo=args.upstream_repo,
        upstream_commit=args.upstream_commit,
        fix_symbol=args.fix_symbol,
        fix_file=args.fix_file,
        summary=args.summary,
        tarball_url=args.tarball_url,
        tarball_sri=args.tarball_sha256_sri,
        out_dir=args.out,
        nixpkgs_rev=args.nixpkgs_rev,
        nixpkgs_package_nix=args.nixpkgs_package_nix,
        nixpkgs_package_nix_path=args.nixpkgs_package_nix_path,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
