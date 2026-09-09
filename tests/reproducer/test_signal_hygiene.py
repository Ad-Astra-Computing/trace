"""Unit coverage for the vacuous-signal scanner (DECISIONS 2026-09-08, svgo)."""

from __future__ import annotations

import pytest

from agents.reproducer.signal_hygiene import describe, refuses, scan_arm


@pytest.mark.parametrize(
    "text",
    [
        "grep: namespaced-out.svg: No such file or directory",
        "cat: out.json: No such file or directory",
        "  stat: /tmp/result.bin: No such file or directory",
    ],
)
def test_a_predicate_helper_reading_a_missing_file_is_a_mark(text):
    assert scan_arm(text).missing_read, text
    # Alone it is shown, not gated on: a healthy fixture may cat an optional file.
    assert not refuses({"patched": scan_arm(text)}), text


@pytest.mark.parametrize(
    "text",
    [
        "error: unknown option '--enable=removeScripts'",
        "foo: unrecognized option '--metadata'",
        "wget2: invalid option -- 'z'",
        "usage: svgo [options] [INPUT...]",
        "sh: line 1: svgo: command not found",
    ],
)
def test_a_refused_invocation_alone_is_a_mark_but_does_not_gate(text):
    """A tool may print help while doing its work, and rejecting a bad option may
    be the behaviour under test."""
    marks = scan_arm(text)
    assert marks.refused_invocation, text
    assert not marks.missing_read, text
    assert not refuses({"patched": marks}), text


@pytest.mark.parametrize(
    "text",
    [
        "",
        "parsed 2 files\nSIGNAL_PATCHED: sanitised both payloads\n",
        "wrote out.svg (412 bytes)\n",
        # The package under test complaining about a fixture it was MEANT to reject
        # is not a mark: the tool ran, which is exactly what we are checking for.
        "svgo: could not parse evil.svg: unexpected token at line 3\n",
        # A traversal target the patched arm expects to be absent is checked with
        # `test -e`, which prints nothing; nothing here should match.
        "checking /tmp/owned-by-cve: absent\n",
    ],
)
def test_an_honest_run_is_clean(text):
    assert not scan_arm(text), text


def test_the_real_svgo_arm_is_caught():
    """The bytes that actually reached probe-build.json on 8 September 2026."""
    arm = (
        "building '/nix/store/xxx-repro-CVE-2026-73650-patched.drv'...\n"
        "error: unknown option '--enable=removeScripts'\n"
        "error: unknown option '--enable=removeScripts'\n"
        "grep: namespaced-out.svg: No such file or directory\n"
        "grep: case-out.svg: No such file or directory\n"
        "sanitized: namespaced script element and mixed-case javascript: URI both removed\n"
        "SIGNAL_PATCHED: sanitized: namespaced script element and mixed-case javascript: URI both removed\n"
    )
    marks = scan_arm(arm)
    assert marks.damning, "refused the invocation, then read the output it never wrote"
    assert any("namespaced-out.svg" in m for m in marks.missing_read)
    assert any("unknown option" in m for m in marks.refused_invocation)
    assert refuses({"patched": marks})


def test_describe_separates_a_refusal_from_an_advisory():
    assert "never happened" not in describe({})
    lone = describe({"patched": scan_arm("grep: x: No such file or directory")})
    assert "advisory" in lone and "never happened" not in lone
    pair = describe(
        {
            "patched": scan_arm(
                "demo: unknown option '--nope'\ngrep: x: No such file or directory\n"
            )
        }
    )
    assert "never happened" in pair


def test_one_mark_of_each_kind_in_DIFFERENT_arms_does_not_gate():
    """The pair has to sit in the same arm. Two unrelated marks across the two
    arms is not the svgo signature."""
    from agents.reproducer.signal_hygiene import scan_build

    build = {
        "unpatched": {
            "stdout_stderr": "cat: optional.txt: No such file or directory\nSIGNAL_UNPATCHED: x\n"
        },
        "patched": {
            "stdout_stderr": "usage: demo [opts]\nprocessed\nSIGNAL_PATCHED: y\n"
        },
    }
    marks = scan_build(build, signals={"unpatched": True, "patched": True})
    assert marks, "both arms carry a mark worth showing"
    assert not refuses(marks), "but neither arm carries the pair"


def test_an_incidental_missing_file_in_a_healthy_run_does_not_gate():
    """A fixture that cats an optional file, then runs the tool successfully and
    emits its signal, must not be blocked."""
    arm = (
        "cat: optional-output: No such file or directory\n"
        "demo: processed 2 inputs, wrote result.svg\n"
        "SIGNAL_PATCHED: sanitised\n"
    )
    marks = scan_arm(arm)
    assert marks.missing_read
    assert not marks.damning
    assert not refuses({"patched": marks})


def test_a_missing_read_in_a_truncated_log_gates_on_its_own():
    """Builder keeps only the tail of a long arm. A refusal happens at invocation,
    so it is exactly the mark truncation eats; a missing read that survives is
    then enough on its own."""
    import hashlib

    from agents.reproducer.signal_hygiene import scan_build

    tail = "grep: out.svg: No such file or directory\nSIGNAL_PATCHED: sanitised\n"
    build = {
        "patched": {
            "stdout_stderr": tail,
            # the digest of the FULL log, which we were not given
            "stdout_stderr_log_sha256": hashlib.sha256(
                b"...much more output..."
            ).hexdigest(),
        }
    }
    marks = scan_build(build, signals={"patched": True})
    assert marks["patched"].truncated
    assert refuses(marks)
    assert "truncated" in describe(marks)


def test_an_untruncated_log_still_needs_the_pair():
    import hashlib

    from agents.reproducer.signal_hygiene import scan_build

    tail = "cat: optional.txt: No such file or directory\ndemo ran fine\nSIGNAL_PATCHED: ok\n"
    build = {
        "patched": {
            "stdout_stderr": tail,
            "stdout_stderr_log_sha256": hashlib.sha256(tail.encode()).hexdigest(),
        }
    }
    marks = scan_build(build, signals={"patched": True})
    assert not marks["patched"].truncated
    assert not refuses(marks)
