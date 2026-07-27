"""Regenerate an honest adaptation-lane applicability attestation.

This is a deterministic, no-model-spend replica of the attestation-emission
step the Patcher performs for adaptation-lane bundles (see
``tools/trace_cli/execute.py`` around the ``canonicalize_backport_patch``
call, roughly lines 739-811). It exists so that eval-only fixtures under
``traces/eval-adaptation/`` — which are hand-authored / hand-corrupted from
template bundles rather than produced by a live Patcher run — can carry a
genuinely honest ``patch-applicability.json`` instead of a stale or
hand-forged one.

Given a bundle directory, this script:

  1. Reads ``patch.diff`` and every file under ``source-context/``.
  2. Computes ``raw_patch_sha256`` over the on-disk ``patch.diff`` bytes
     BEFORE canonicalization.
  3. Runs ``canonicalize_backport_patch`` (the same canonical compiler the
     Patcher invokes) over the diff text against the source-context.
  4. Re-writes ``patch.diff`` with the canonical bytes (a no-op if the patch
     was already canonical; a real rewrite otherwise — this mirrors the
     Patcher's own on-disk write, since the canonical patch is the artifact
     Builder actually executes).
  5. Computes ``canonical_patch_sha256`` over the canonical bytes.
  6. Writes ``patch-applicability.json`` with the same schema and key set the
     Patcher emits, attesting (truthfully, by construction of the canonical
     compiler) that the patch applies at fuzz 0 and is uniquely grounded in
     source-context.

This does not fix, alter, or launder the *meaning* of the patch — dangling
symbols, semantic bugs, and other defects in the model/hand-authored body
survive canonicalization unchanged and remain visible to the Reviewer. Only
the diff's *representation* (hunk headers, redundant del/re-add, trailing
context) is normalized.

Usage:

    PYTHONPATH=. nix develop --command python3 \\
        scripts/regen_eval_attestation.py <bundle-dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tools.trace_cli.execute import sha256_hex
from tools.trace_cli.hunk_normalizer import (
    CANONICALIZER_VERSION,
    canonicalize_backport_patch,
)


def regen(bundle_dir: Path) -> dict:
    """Regenerate patch.diff (canonicalized) + patch-applicability.json.

    Returns the attestation dict that was written, for callers that want to
    inspect the result without re-reading the file.
    """
    patch_path = bundle_dir / "patch.diff"
    sc_dir = bundle_dir / "source-context"

    diff_text = patch_path.read_text()
    source_context = {
        str(p.relative_to(sc_dir)): p.read_text()
        for p in sc_dir.rglob("*")
        if p.is_file()
    }

    pre_sha = sha256_hex(diff_text.encode("utf-8"))

    canon = canonicalize_backport_patch(diff_text, source_context)

    diff_bytes = canon.text.encode("utf-8")
    if diff_bytes and not diff_bytes.endswith(b"\n"):
        diff_bytes += b"\n"

    post_sha = sha256_hex(diff_bytes)

    patch_path.write_bytes(diff_bytes)

    attestation = {
        "schema_version": "1.0.0",
        "canonicalizer_version": CANONICALIZER_VERSION,
        "raw_patch_sha256": pre_sha,
        "canonical_patch_sha256": post_sha,
        "canonicalized": canon.changed,
        "unique_source_match": True,
        "applies_at_fuzz0": True,
        "files": canon.files,
    }

    att_bytes = json.dumps(attestation, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    (bundle_dir / "patch-applicability.json").write_bytes(att_bytes)

    return attestation


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <bundle-dir>", file=sys.stderr)
        return 2
    bundle_dir = Path(argv[1])
    if not bundle_dir.is_dir():
        print(f"error: not a directory: {bundle_dir}", file=sys.stderr)
        return 2
    attestation = regen(bundle_dir)
    print(json.dumps(attestation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
