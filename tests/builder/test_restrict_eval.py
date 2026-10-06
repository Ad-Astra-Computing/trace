"""restrict-eval actually closes the model-authored-reproducer.nix exfil
path (S1, fable audit 2026-10-06): `builtins.readFile` of a path outside
the allowed roots, and any `fetchurl`/`fetchTarball` URI, must be refused
at eval time regardless of fetcher-alias tricks that bypass the lexical
denylist in `agents/reproducer/parser.py`. Legitimate bundle-relative
reads (fixtures under the bundle dir) must still work.

Runs against the real `nix-build`; skips cleanly where it isn't on PATH.
"""

from __future__ import annotations

import shutil

import pytest

from agents.builder.protocol import LocalNixBuildRunner

pytestmark = pytest.mark.skipif(
    shutil.which("nix-build") is None,
    reason="nix-build not on PATH",
)


def test_readfile_outside_allowed_roots_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("sk-ant-should-not-be-readable\n")

    allowed = tmp_path / "bundle"
    allowed.mkdir()

    expr = f'builtins.readFile "{secret}"'
    outcome = LocalNixBuildRunner().run(
        nix_expression=expr,
        cwd=allowed,
        allowed_roots=[allowed],
        timeout_seconds=60,
    )
    assert outcome.exit_code != 0
    assert "forbidden" in outcome.stdout_stderr.lower()


def test_fetchurl_alias_bypassing_the_lexical_denylist_is_refused(tmp_path):
    allowed = tmp_path / "bundle"
    allowed.mkdir()

    # `agents/reproducer/parser.py` denylists the literal token
    # `builtins.fetchurl`; this expression reaches the same builtin
    # through an alias, which the lexical regex does not catch.
    expr = (
        "let b = builtins; in "
        'b.fetchurl { url = "https://example.invalid/x"; '
        'sha256 = "0000000000000000000000000000000000000000000000000000"; }'
    )
    outcome = LocalNixBuildRunner().run(
        nix_expression=expr,
        cwd=allowed,
        allowed_roots=[allowed],
        timeout_seconds=60,
    )
    assert outcome.exit_code != 0
    assert "forbidden" in outcome.stdout_stderr.lower()


def test_readfile_inside_an_allowed_root_still_works(tmp_path):
    allowed = tmp_path / "bundle"
    allowed.mkdir()
    fixture = allowed / "fixture.txt"
    fixture.write_text("legitimate-fixture-content\n")

    # derivation()-shaped so nix-build accepts the result; the point under
    # test is that the readFile itself is permitted, not the build output.
    expr = (
        "derivation { "
        'name = "ok"; system = builtins.currentSystem; builder = "/bin/sh"; '
        'args = [ "-c" "echo ok > $out" ]; '
        f'content = builtins.readFile "{fixture}"; '
        "}"
    )
    outcome = LocalNixBuildRunner().run(
        nix_expression=expr,
        cwd=allowed,
        allowed_roots=[allowed],
        timeout_seconds=60,
    )
    assert "forbidden" not in outcome.stdout_stderr.lower()
