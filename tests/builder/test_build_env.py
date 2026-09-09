"""The environment a model-authored fixture is evaluated under.

`nix-build` evaluates reproducer.nix with the parent environment. On an
operator's machine that environment routinely holds live API keys, and the
build log is committed to a public repository, so the evaluator must see an
allow-list rather than everything.
"""

from __future__ import annotations

from unittest import mock

from agents.builder.protocol import LocalNixBuildRunner, build_environment


def test_secrets_are_dropped_and_toolchain_vars_kept():
    parent = {
        "PATH": "/nix/store/x/bin",
        "HOME": "/home/agent",
        "TMPDIR": "/tmp",
        "NIX_PATH": "nixpkgs=/x",
        "NIX_SSL_CERT_FILE": "/etc/ssl/certs/ca-bundle.crt",
        "NIX_CONFIG": "experimental-features = nix-command",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "ANTHROPIC_API_KEY": "sk-ant-secret",
        "HF_TOKEN": "hf_secret",
        "GITHUB_TOKEN": "ghp_secret",
        "AWS_SECRET_ACCESS_KEY": "aws",
        "SOME_RANDOM_APP_VAR": "x",
    }
    env = build_environment(parent)
    for kept in (
        "PATH",
        "HOME",
        "TMPDIR",
        "NIX_PATH",
        "NIX_SSL_CERT_FILE",
        "NIX_CONFIG",
        "LANG",
        "LC_ALL",
    ):
        assert env[kept] == parent[kept]
    for dropped in (
        "ANTHROPIC_API_KEY",
        "HF_TOKEN",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "SOME_RANDOM_APP_VAR",
    ):
        assert dropped not in env


def test_instrumentation_override_is_set_on_top_of_the_allow_list():
    env = build_environment(
        {"PATH": "/bin", "ANTHROPIC_API_KEY": "x"}, instrumentation="asan"
    )
    assert env["TRACE_INSTRUMENTATION"] == "asan"
    assert "ANTHROPIC_API_KEY" not in env


def test_runner_passes_the_allow_listed_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-reach-nix")
    monkeypatch.setenv("PATH", "/nix/store/fake/bin")
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw["env"]
        return mock.Mock(returncode=0, stdout="/nix/store/out\n", stderr="")

    with (
        mock.patch(
            "agents.builder.protocol.shutil.which",
            return_value="/nix/store/fake/bin/nix-build",
        ),
        mock.patch("agents.builder.protocol.subprocess.run", side_effect=fake_run),
    ):
        LocalNixBuildRunner().run(attr="unpatched.test", cwd=tmp_path)
    assert "ANTHROPIC_API_KEY" not in seen["env"]
    assert seen["env"]["PATH"] == "/nix/store/fake/bin"


def test_cached_build_reads_the_stored_log(tmp_path):
    """A derivation already in the store prints only its path, so the signal
    lines never reach stdout. The stored build log is the same evidence: the
    derivation is addressed by its inputs, so the log describes this exact
    build. Both live probes went red on their second run for this reason."""
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[0].endswith("nix-build"):
            return mock.Mock(
                returncode=0, stdout="/nix/store/abc-repro-unpatched\n", stderr=""
            )
        if cmd[0].endswith("nix-store"):
            assert cmd[1:] == ["--read-log", "/nix/store/abc-repro-unpatched"]
            return mock.Mock(
                returncode=0, stdout="SIGNAL_UNPATCHED: vuln-triggered\n", stderr=""
            )
        raise AssertionError(cmd)

    with (
        mock.patch(
            "agents.builder.protocol.shutil.which",
            side_effect=lambda b: f"/nix/store/fake/bin/{b}",
        ),
        mock.patch("agents.builder.protocol.subprocess.run", side_effect=fake_run),
    ):
        outcome = LocalNixBuildRunner().run(attr="unpatched.test", cwd=tmp_path)
    assert outcome.out_path == "/nix/store/abc-repro-unpatched"
    assert "SIGNAL_UNPATCHED: vuln-triggered" in outcome.stdout_stderr


def test_streamed_log_is_not_duplicated(tmp_path):
    streamed = "building '/nix/store/x.drv'...\nSIGNAL_UNPATCHED: vuln-triggered\n/nix/store/abc-out\n"

    def fake_run(cmd, **kw):
        if cmd[0].endswith("nix-build"):
            return mock.Mock(returncode=0, stdout=streamed, stderr="")
        return mock.Mock(
            returncode=0, stdout="SIGNAL_UNPATCHED: vuln-triggered\n", stderr=""
        )

    with (
        mock.patch(
            "agents.builder.protocol.shutil.which",
            side_effect=lambda b: f"/nix/store/fake/bin/{b}",
        ),
        mock.patch("agents.builder.protocol.subprocess.run", side_effect=fake_run),
    ):
        outcome = LocalNixBuildRunner().run(attr="unpatched.test", cwd=tmp_path)
    assert outcome.stdout_stderr.count("SIGNAL_UNPATCHED: vuln-triggered") == 1


def test_nix_config_access_tokens_are_stripped():
    """NIX_CONFIG is allow-listed for experimental-features and substituters, but
    it can also carry `access-tokens = host=TOKEN` for a private cache, which a
    hostile fixture could read through builtins.getEnv."""
    parent = {
        "PATH": "/bin",
        "NIX_CONFIG": "experimental-features = nix-command flakes\naccess-tokens = github.com=ghp_"
        + "a" * 36
        + "\nsubstituters = https://cache.nixos.org",
    }
    env = build_environment(parent)
    assert "access-tokens" not in env["NIX_CONFIG"]
    assert "ghp_" not in env["NIX_CONFIG"]
    assert "experimental-features = nix-command flakes" in env["NIX_CONFIG"]
    assert "substituters = https://cache.nixos.org" in env["NIX_CONFIG"]
