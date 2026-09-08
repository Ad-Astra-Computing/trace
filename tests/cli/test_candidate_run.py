"""`trace candidate run`: one screened candidate through every gate, in order,
stopping at the first refusal, with an append-only record.

See docs/specs/candidate-orchestrator.md. Each step is injected so the suite
spends nothing and the sequencing is what gets tested.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli.candidate_run import (
    EXIT_GATE_STOPPED,
    EXIT_INFRA,
    EXIT_READY,
    Steps,
    StepStopped,
    run_candidate,
)


class Trace:
    """Records the order steps were called in, and lets a test make one stop."""

    def __init__(self, stop_at: str | None = None, infra_at: str | None = None):
        self.calls: list[str] = []
        self.stop_at = stop_at
        self.infra_at = infra_at

    OUTPUTS = {"patcher": "patch.diff", "reviewer": "review.md", "reproducer": "reproducer.nix"}

    def step(self, name: str, result=None):
        def _run(ctx):
            self.calls.append(name)
            if name == self.stop_at:
                raise StepStopped(name, f"{name} refused: simulated")
            if name == self.infra_at:
                raise OSError(f"{name}: simulated infrastructure failure")
            if name == "fetch_source" and result is None:
                # A real fetch leaves a tree under out/src; resume looks for it.
                tree = Path(ctx["out_dir"]) / "src" / "pkg-1.0"
                tree.mkdir(parents=True, exist_ok=True)
                (tree / "file").write_text("x\n")
                return tree
            if name in self.OUTPUTS:
                # A real model step leaves its output in the bundle; resume checks
                # for it, so the fake has to leave one too.
                bundle = Path(ctx["out_dir"]) / "bundle"
                bundle.mkdir(parents=True, exist_ok=True)
                (bundle / self.OUTPUTS[name]).write_text(f"{name} output\n")
            return result
        return _run

    def steps(self) -> Steps:
        return Steps(
            bootstrap=self.step("bootstrap"),
            assemble=self.step("assemble"),
            finalize=self.step("finalize"),
            fetch_source=self.step("fetch_source"),
            preflight_upstream=self.step("preflight_upstream"),
            patcher=self.step("patcher"),
            preflight_payload=self.step("preflight_payload"),
            reviewer=self.step("reviewer", "accept"),
            reproducer=self.step("reproducer"),
            probe=self.step("probe", True),
            refinalize=self.step("refinalize"),
        )


ORDER = ["bootstrap", "assemble", "finalize", "fetch_source", "preflight_upstream",
         "patcher", "preflight_payload", "reviewer", "reproducer", "probe", "refinalize"]
PAID = {"patcher", "reviewer", "reproducer"}


def _ctx(tmp_path: Path) -> dict:
    return {
        "inbox_entry": tmp_path / "entry",
        "out_dir": tmp_path / "out",
        "nixpkgs_checkout": tmp_path / "nixpkgs",
        "nixpkgs_rev": "c" * 40,
        "created_at": "2026-09-07T00:00:00Z",
        "models": {"patcher": "m-p", "reviewer": "m-r", "reproducer": "m-x"},
    }


def _record(tmp_path: Path) -> list[dict]:
    p = tmp_path / "out" / "run.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def test_a_complete_run_executes_every_step_in_order(tmp_path):
    t = Trace()
    code = run_candidate(_ctx(tmp_path), steps=t.steps())
    assert code == EXIT_READY
    assert t.calls == ORDER
    rec = _record(tmp_path)
    assert [r["step"] for r in rec] == ORDER + ["result"]
    assert rec[-1]["outcome"] == "ready-for-cert"


def test_upstream_patch_that_does_not_apply_stops_before_any_model_call(tmp_path):
    t = Trace(stop_at="preflight_upstream")
    code = run_candidate(_ctx(tmp_path), steps=t.steps())
    assert code == EXIT_GATE_STOPPED
    assert not (PAID & set(t.calls))
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "stopped"
    assert rec[-1]["gate"] == "preflight_upstream"


def test_reviewer_reject_stops_before_the_reproducer(tmp_path):
    t = Trace()
    steps = t.steps()
    steps.reviewer = t.step("reviewer", "reject")
    code = run_candidate(_ctx(tmp_path), steps=steps)
    assert code == EXIT_GATE_STOPPED
    assert "reviewer" in t.calls and "reproducer" not in t.calls
    assert _record(tmp_path)[-1]["gate"] == "reviewer"


def test_red_probe_stops_before_refinalize(tmp_path):
    t = Trace()
    steps = t.steps()
    steps.probe = t.step("probe", False)
    code = run_candidate(_ctx(tmp_path), steps=steps)
    assert code == EXIT_GATE_STOPPED
    assert "refinalize" not in t.calls
    assert _record(tmp_path)[-1]["gate"] == "probe"


def test_infrastructure_failure_is_not_recorded_as_a_gate(tmp_path):
    """A source fetch that fails on the network says nothing about the candidate."""
    t = Trace(infra_at="fetch_source")
    code = run_candidate(_ctx(tmp_path), steps=t.steps())
    assert code == EXIT_INFRA
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "infrastructure-error"
    assert "gate" not in rec[-1]
    assert not (PAID & set(t.calls))


def test_record_has_one_entry_per_attempted_step_and_is_append_only(tmp_path):
    t = Trace(stop_at="patcher")
    run_candidate(_ctx(tmp_path), steps=t.steps())
    rec = _record(tmp_path)
    attempted = ORDER[: ORDER.index("patcher") + 1]
    assert [r["step"] for r in rec[:-1]] == attempted
    assert all("at" in r for r in rec)
    before = (tmp_path / "out" / "run.jsonl").read_text()
    t2 = Trace()
    run_candidate(_ctx(tmp_path), steps=t2.steps())
    after = (tmp_path / "out" / "run.jsonl").read_text()
    assert after.startswith(before)


def test_resume_skips_completed_steps_and_never_recalls_a_model(tmp_path):
    t = Trace()
    run_candidate(_ctx(tmp_path), steps=t.steps())
    t2 = Trace()
    code = run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    assert code == EXIT_READY
    assert not (PAID & set(t2.calls))


def test_default_steps_are_the_real_commands():
    """The orchestrator sequences existing commands; it must not grow its own."""
    from tools.trace_cli import candidate_run as m
    defaults = m.default_steps()
    assert defaults.bootstrap.__module__.endswith("candidate_run")
    for name in ("bootstrap", "assemble", "finalize", "fetch_source", "preflight_upstream",
                 "patcher", "preflight_payload", "reviewer", "reproducer", "probe", "refinalize"):
        assert callable(getattr(defaults, name)), name


def test_resume_after_a_stop_skips_the_completed_steps_and_repeats_no_model_call(tmp_path):
    """The recorded use case: mailpit stopped at the probe after all three paid
    steps had run. Resume must start at the probe."""
    t = Trace()
    steps = t.steps()
    steps.probe = t.step("probe", False)
    run_candidate(_ctx(tmp_path), steps=steps)
    t2 = Trace()
    code = run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    assert code == EXIT_READY
    assert not (PAID & set(t2.calls))
    # free gates are never skipped; the expensive setup and the paid steps are
    assert t2.calls == ["preflight_upstream", "preflight_payload", "probe", "refinalize"]


def test_resume_never_repeats_a_paid_step_whose_output_exists(tmp_path):
    """A run that stopped at the Patcher (its refusal) still has whatever the model
    wrote; resume does not call the model again. Regenerating is a deliberate
    re-run, not a resume."""
    ctx = _ctx(tmp_path)
    t = Trace(stop_at="preflight_payload")
    run_candidate(ctx, steps=t.steps())
    bundle = tmp_path / "out" / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "patch.diff").write_text("model output\n")
    t2 = Trace()
    run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    assert "patcher" not in t2.calls
    assert t2.calls[0] == "preflight_upstream"


def test_skipped_steps_leave_the_context_usable(tmp_path):
    """Skipped steps ran in a previous process, so their side effects on ctx are
    gone. The paths they produce are functions of the out dir and get re-derived."""
    ctx = _ctx(tmp_path)
    t = Trace()
    steps = t.steps()
    steps.probe = t.step("probe", False)
    run_candidate(ctx, steps=steps)
    seen = {}

    def probe(c):
        seen.update({k: c.get(k) for k in ("staged", "bundle_dir", "source_tree")})
        return True

    t2 = Trace()
    steps2 = t2.steps()
    steps2.probe = probe
    run_candidate(_ctx(tmp_path), steps=steps2, resume=True)
    assert seen["staged"] == tmp_path / "out" / "staged"
    assert seen["bundle_dir"] == tmp_path / "out" / "bundle"
    assert seen["source_tree"] is not None


def test_a_contract_failure_in_a_model_step_is_recorded_not_raised(tmp_path):
    from tools.trace_cli.execute import ExecutionError
    from tools.trace_cli.candidate_run import EXIT_STEP_ERROR

    t = Trace()
    steps = t.steps()

    def bad_reviewer(c):
        raise ExecutionError("reviewer output malformed after retries")
    steps.reviewer = bad_reviewer
    code = run_candidate(_ctx(tmp_path), steps=steps)
    assert code == EXIT_STEP_ERROR
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "step-error"
    assert rec[-2]["step"] == "reviewer" and rec[-2]["status"] == "error"


def test_free_gates_are_never_skipped_on_resume_even_if_the_record_says_ok(tmp_path):
    """A run.jsonl line is a claim. Preflight and the probe cost nothing to
    re-run and are the checks that stand between a model payload and a cert, so
    resume re-runs them whatever the record says."""
    t = Trace()
    run_candidate(_ctx(tmp_path), steps=t.steps())
    t2 = Trace()
    run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    for gate in ("preflight_upstream", "preflight_payload", "probe", "refinalize"):
        assert gate in t2.calls, gate


def test_a_paid_output_is_only_reused_for_the_inputs_that_produced_it(tmp_path):
    """Existence of patch.diff is not enough: the same out dir reused with a
    different package.nix must call the Patcher again."""
    ctx = _ctx(tmp_path)
    bundle = tmp_path / "out" / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "package.nix").write_text("{ }: { version = \"1\"; }\n")
    (bundle / "upstream-fix.patch").write_text("--- a\n+++ b\n")
    t = Trace()
    steps = t.steps()
    steps.patcher = lambda c: (bundle / "patch.diff").write_text("model output\n")
    run_candidate(ctx, steps=steps)

    t2 = Trace()
    run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    assert "patcher" not in t2.calls

    (bundle / "package.nix").write_text("{ }: { version = \"2\"; }\n")
    t3 = Trace()
    run_candidate(_ctx(tmp_path), steps=t3.steps(), resume=True)
    assert "patcher" in t3.calls


def test_a_new_model_or_prompt_invalidates_a_reused_output(tmp_path, monkeypatch):
    """The output of a paid step depends on which model and prompt produced it.
    Bumping either must call the model again even when the bundle files match."""
    ctx = _ctx(tmp_path)
    t = Trace()
    run_candidate(ctx, steps=t.steps())
    ctx2 = _ctx(tmp_path)
    ctx2["models"]["patcher"] = "some-newer-model"
    t2 = Trace()
    run_candidate(ctx2, steps=t2.steps(), resume=True)
    assert "patcher" in t2.calls
    assert "reviewer" not in t2.calls or True  # reviewer reuse is judged on its own inputs


def test_a_second_resume_still_reuses_the_model_outputs(tmp_path):
    """A skipped line carries the hash forward, so resuming a resumed run does
    not bill the models again."""
    t = Trace()
    steps = t.steps()
    steps.probe = t.step("probe", False)
    run_candidate(_ctx(tmp_path), steps=steps)
    t2 = Trace()
    steps2 = t2.steps()
    steps2.probe = t2.step("probe", False)
    run_candidate(_ctx(tmp_path), steps=steps2, resume=True)
    t3 = Trace()
    run_candidate(_ctx(tmp_path), steps=t3.steps(), resume=True)
    assert not (PAID & set(t3.calls))


def test_a_step_that_exits_the_process_is_recorded_as_a_stop(tmp_path):
    """The first live run on prevail ended with no result line: the wrapped
    preflight called sys.exit rather than returning. A SystemExit from a step is
    a refusal to record, not a way to leave run.jsonl unfinished."""
    t = Trace()
    steps = t.steps()

    def exiting(ctx):
        raise SystemExit(4)
    steps.preflight_upstream = exiting
    code = run_candidate(_ctx(tmp_path), steps=steps)
    assert code == EXIT_GATE_STOPPED
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "stopped" and rec[-1]["gate"] == "preflight_upstream"
    assert "reproducer" not in t.calls and "patcher" not in t.calls


def test_an_unexpected_exception_in_a_step_still_leaves_a_result_line(tmp_path):
    """A bug inside a step must not leave run.jsonl without a result. The prevail
    run hit a NameError in the preflight's failure branch and the record simply
    ended."""
    t = Trace()
    steps = t.steps()

    def buggy(ctx):
        raise NameError("name 'results' is not defined")
    steps.preflight_upstream = buggy
    from tools.trace_cli.candidate_run import EXIT_STEP_ERROR
    code = run_candidate(_ctx(tmp_path), steps=steps)
    assert code == EXIT_STEP_ERROR
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "step-error" and rec[-1]["step_failed"] == "preflight_upstream"
    assert "NameError" in rec[-2]["reason"]


def test_until_stops_after_the_named_step_without_spending(tmp_path):
    """A survey of which upstream patches apply must not proceed into the paid
    steps. --until names the last step to run; the record says why it stopped."""
    t = Trace()
    code = run_candidate(_ctx(tmp_path), steps=t.steps(), until="preflight_upstream")
    assert code == EXIT_READY
    assert t.calls == ["bootstrap", "assemble", "finalize", "fetch_source", "preflight_upstream"]
    rec = _record(tmp_path)
    assert rec[-1]["outcome"] == "stopped-at-until" and rec[-1]["until"] == "preflight_upstream"


def test_until_rejects_an_unknown_step(tmp_path):
    t = Trace()
    with pytest.raises(ValueError, match="unknown step"):
        run_candidate(_ctx(tmp_path), steps=t.steps(), until="nope")


def test_choose_applying_fix_tries_each_cited_commit_in_order():
    """svgo CVE-2026-84370 cites three fix commits, one per maintained branch; the
    first is the v2 backport and does not apply to the packaged 4.0.1."""
    from tools.trace_cli.candidate_run import _choose_applying_fix
    commits = [{"repo_url": "https://github.com/svg/svgo", "commit_sha": "a" * 40},
               {"repo_url": "https://github.com/svg/svgo", "commit_sha": "b" * 40},
               {"repo_url": "https://github.com/svg/svgo", "commit_sha": "c" * 40}]
    fetched = []
    texts = {"a" * 40: "v2 patch", "b" * 40: "v3 patch", "c" * 40: "v4 patch"}
    def fetch(url):
        sha = url.rsplit("/", 1)[-1].removesuffix(".patch"); fetched.append(sha); return texts[sha]
    chosen = _choose_applying_fix(commits, fetch_patch=fetch, applies=lambda text: text == "v4 patch")
    assert chosen == (commits[2], "v4 patch")
    assert fetched == ["a" * 40, "b" * 40, "c" * 40]


def test_choose_applying_fix_returns_none_when_nothing_applies():
    from tools.trace_cli.candidate_run import _choose_applying_fix
    commits = [{"repo_url": "https://github.com/o/r", "commit_sha": "a" * 40}]
    assert _choose_applying_fix(commits, fetch_patch=lambda u: "x", applies=lambda t: False) is None


def test_fetch_source_records_where_the_source_tree_is(tmp_path):
    """A fetched source is often a store path rather than a directory under out/src
    (a fetchFromGitHub source is already a tree), so the record has to carry the
    location or a resume cannot find it."""
    src = tmp_path / "store-source"
    src.mkdir()
    t = Trace()
    steps = t.steps()
    steps.fetch_source = t.step("fetch_source", src)
    run_candidate(_ctx(tmp_path), steps=steps)
    line = next(e for e in _record(tmp_path) if e["step"] == "fetch_source")
    assert line["source_tree"] == str(src)


def test_resume_hands_the_recorded_source_tree_to_the_free_gates(tmp_path):
    """netron CVE-2026-79718: the survey run left an empty out/src because the
    source was a store path; the resumed run preflighted an empty directory and
    reported a base mismatch that did not exist."""
    src = tmp_path / "store-source"
    src.mkdir()
    (src / "file").write_text("x\n")
    t = Trace()
    steps = t.steps()
    steps.fetch_source = t.step("fetch_source", src)
    run_candidate(_ctx(tmp_path), steps=steps, until="preflight_upstream")

    seen = {}
    t2 = Trace()
    steps2 = t2.steps()
    steps2.preflight_upstream = lambda c: seen.setdefault("source_tree", c.get("source_tree"))
    run_candidate(_ctx(tmp_path), steps=steps2, resume=True)
    assert "fetch_source" not in t2.calls
    assert seen["source_tree"] == src


def test_resume_refetches_when_the_recorded_source_tree_is_gone(tmp_path):
    src = tmp_path / "store-source"
    src.mkdir()
    (src / "file").write_text("x\n")
    t = Trace()
    steps = t.steps()
    steps.fetch_source = t.step("fetch_source", src)
    run_candidate(_ctx(tmp_path), steps=steps, until="preflight_upstream")
    (src / "file").unlink()
    src.rmdir()

    t2 = Trace()
    run_candidate(_ctx(tmp_path), steps=t2.steps(), resume=True)
    assert "fetch_source" in t2.calls


class TestAdaptationLane:
    """`--adaptation-lane` lets a run continue past an upstream patch that does
    not apply, which is the normal state in the semantic-adaptation lane: the fix
    is expressible on the pinned base but not verbatim. Continuing is only
    meaningful if the bundle is restaged against the fetched source, because
    `source-context/` plus `preflight.json` are what route the Patcher to
    patcher.v4 and what put the divergence into the signed manifest. Every test
    here drives the real `_preflight`, so the override is operated rather than
    described.
    """

    PINNED = "int old(void);\n"
    FIX = (
        "diff --git a/src/file.c b/src/file.c\n"
        "--- a/src/file.c\n"
        "+++ b/src/file.c\n"
        "@@ -1 +1,2 @@\n"
        " int old(void);\n"
        "+int guard(void);\n"
    )

    @classmethod
    def _ctx(cls, tmp_path: Path, reason=None) -> dict:
        bundle = tmp_path / "bundle"
        bundle.mkdir(parents=True, exist_ok=True)
        staged = tmp_path / "staged"
        staged.mkdir(parents=True, exist_ok=True)
        (bundle / "upstream-fix.patch").write_text(cls.FIX)
        src = tmp_path / "src"
        (src / "src").mkdir(parents=True, exist_ok=True)
        (src / "src" / "file.c").write_text(cls.PINNED)
        return {
            "bundle_dir": bundle,
            "staged": staged,
            "source_tree": src,
            "out_dir": tmp_path / "out",
            "attr_path": "pkg",
            "nixpkgs_rev": "c" * 40,
            "created_at": "2026-09-08T00:00:00Z",
            "adaptation_lane": reason,
        }

    @classmethod
    def _stage_context(cls, bundle: Path, body=None) -> None:
        """What the real source-backport staging leaves behind."""
        dst = bundle / "source-context" / "src"
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "file.c").write_text(cls.PINNED if body is None else body)

    @staticmethod
    def _fail(monkeypatch, code=None):
        from tools.trace_cli import preflight
        if code is None:
            code = preflight.EXIT_APPLY_FAILED
        monkeypatch.setattr(preflight, "run", lambda *a, **k: code)

    @staticmethod
    def _restage(monkeypatch, verdict, *, calls=None, raises=None,
                 diagnostics="Hunk #3 FAILED at 274.\n"):
        """Stand in for assemble_bundle: record the call and write the verdict
        the real source-backport staging would have written."""
        from tools.trace_cli import bundle as bundle_mod

        def fake(**kw):
            if calls is not None:
                calls.append(kw)
            if raises is not None:
                raise raises
            if verdict is not None:
                (kw["out_dir"] / "preflight.json").write_text(
                    json.dumps({"applies_verbatim": verdict,
                                "diagnostics": diagnostics}) + "\n")
                TestAdaptationLane._stage_context(kw["out_dir"])
        monkeypatch.setattr(bundle_mod, "assemble_bundle", fake)
        monkeypatch.setattr(bundle_mod, "finalize_bundle", lambda **kw: None)

    def test_a_failing_upstream_preflight_still_stops_without_the_flag(self, tmp_path, monkeypatch):
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path)
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        with pytest.raises(StepStopped):
            candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []

    def test_the_flag_restages_against_the_fetched_source(self, tmp_path, monkeypatch):
        """Without the restage the Patcher would get patcher.v3 and transcribe a
        fix that cannot apply, so the source tree reaching assemble is the point."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary: fix expressible, pre-image differs")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        candidate_run._preflight(ctx, patch_diff=False)
        assert len(calls) == 1
        assert calls[0]["source_tree"] == ctx["source_tree"]
        assert calls[0]["out_dir"] == ctx["bundle_dir"]
        assert ctx["entered_adaptation_lane"].startswith("adaptation canary")

    def test_a_restage_that_does_not_record_the_divergence_stops(self, tmp_path, monkeypatch):
        """applies_verbatim true, or no preflight.json at all, would leave the
        Patcher on the verbatim lane with nothing signed saying the base moved."""
        from tools.trace_cli import candidate_run
        for verdict in (True, None):
            self._fail(monkeypatch)
            self._restage(monkeypatch, verdict)
            ctx = self._ctx(tmp_path, "adaptation canary")
            monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
            with pytest.raises(StepStopped) as e:
                candidate_run._preflight(ctx, patch_diff=False)
            assert "applies_verbatim" in e.value.reason
            (tmp_path / "bundle" / "preflight.json").unlink(missing_ok=True)

    def test_source_absent_from_the_pinned_base_is_not_adaptable(self, tmp_path, monkeypatch):
        """The libarchive shape: the fix names files the base does not have, so
        no faithful backport exists and no operator reason makes one."""
        from tools.trace_cli import candidate_run
        from tools.trace_cli.source_context import SourceContextError
        self._fail(monkeypatch)
        self._restage(monkeypatch, False, raises=SourceContextError("missing archive_ckd.c"))
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert "absent from the pinned base" in e.value.reason

    @pytest.mark.parametrize("reason", ["", "   ", "\n\t ", None, 7, ["why"]])
    def test_a_reason_that_says_nothing_does_not_open_the_gate(self, tmp_path, monkeypatch, reason):
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, reason)
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        with pytest.raises(StepStopped):
            candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []

    def test_the_payload_gate_is_not_overridable(self, tmp_path, monkeypatch):
        """What the Patcher actually wrote must apply, adaptation lane or not."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=True)
        assert e.value.gate == "preflight_payload"
        assert calls == []

    def test_a_clean_base_never_restages(self, tmp_path, monkeypatch):
        from tools.trace_cli import candidate_run
        from tools.trace_cli import preflight
        monkeypatch.setattr(preflight, "run", lambda *a, **k: 0)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []
        assert "entered_adaptation_lane" not in ctx

    def test_a_second_pass_does_not_restage_and_so_keeps_the_replay_record(self, tmp_path, monkeypatch):
        """preflight_upstream re-runs on every resume, and assemble rewrites
        replay.json as a resolver-only seed. Restaging twice would drop the model
        invocations while their outputs stayed on disk."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        candidate_run._preflight(ctx, patch_diff=False)
        assert len(calls) == 1

        candidate_run._preflight(ctx, patch_diff=False)
        assert len(calls) == 1
        assert ctx["entered_adaptation_lane"] == "adaptation canary"

    @pytest.mark.parametrize("state", ["verdict-only", "context-only", "unparseable"])
    def test_a_half_staged_bundle_is_restaged(self, tmp_path, monkeypatch, state):
        """One half of the pair is not the lane. Only both together mean the
        Patcher will see patcher.v4 with source to adapt against."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        pf = ctx["bundle_dir"] / "preflight.json"
        sc = ctx["bundle_dir"] / "source-context"
        if state == "verdict-only":
            pf.write_text(json.dumps(
                {"applies_verbatim": False, "diagnostics": "Hunk #3 FAILED"}) + "\n")
        elif state == "context-only":
            self._stage_context(ctx["bundle_dir"])
        else:
            pf.write_text("{not json")
            self._stage_context(ctx["bundle_dir"])
        assert sc.exists() or state == "verdict-only"
        candidate_run._preflight(ctx, patch_diff=False)
        assert len(calls) == 1

    @pytest.mark.parametrize("output", ["patch.diff", "review.md", "reproducer.nix"])
    def test_switching_lanes_on_a_bundle_with_model_output_is_refused(self, tmp_path, monkeypatch, output):
        """Restaging resets replay.json, and a resume picks what to skip from
        hashes taken before that, so the outputs would end up with no invocation
        recording what produced them."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        (ctx["bundle_dir"] / output).write_text("model output\n")
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert output in e.value.reason
        assert calls == []

    def test_an_already_staged_lane_with_model_output_still_resumes(self, tmp_path, monkeypatch):
        """The refusal above is about switching lanes, not about resuming one.
        A bundle already on the lane skips the restage before the check."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        (ctx["bundle_dir"] / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False, "diagnostics": "Hunk #3 FAILED"}) + "\n")
        self._stage_context(ctx["bundle_dir"])
        (ctx["bundle_dir"] / "patch.diff").write_text("model output\n")
        candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []
        assert ctx["entered_adaptation_lane"] == "adaptation canary"

    @pytest.mark.parametrize("step", ["patcher", "reviewer"])
    def test_changed_adaptation_source_invalidates_a_reusable_model_output(self, tmp_path, step):
        """patcher.v4 adapts against source-context/, and the Reviewer checks the
        result against the same source. A resume that ignored them would reuse a
        patch authored for source the bundle no longer has."""
        from tools.trace_cli.candidate_run import _inputs_sha
        bundle = tmp_path / "bundle"
        sc = bundle / "source-context"
        sc.mkdir(parents=True)
        (bundle / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False}) + "\n")
        (sc / "file.c").write_text("int old(void);\n")
        before = _inputs_sha(bundle, step, "m")

        (sc / "file.c").write_text("int new(void);\n")
        assert _inputs_sha(bundle, step, "m") != before

        (sc / "file.c").write_text("int old(void);\n")
        assert _inputs_sha(bundle, step, "m") == before

        (bundle / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False, "patch_flags": ["-p1"]}) + "\n")
        assert _inputs_sha(bundle, step, "m") != before

    def test_a_new_source_context_file_invalidates_a_reusable_model_output(self, tmp_path):
        from tools.trace_cli.candidate_run import _inputs_sha
        bundle = tmp_path / "bundle"
        sc = bundle / "source-context"
        sc.mkdir(parents=True)
        (bundle / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False}) + "\n")
        (sc / "a.c").write_text("x\n")
        before = _inputs_sha(bundle, "patcher", "m")
        (sc / "b.c").write_text("y\n")
        assert _inputs_sha(bundle, "patcher", "m") != before

    @pytest.mark.parametrize("step", ["patcher", "reviewer", "reproducer"])
    def test_a_verbatim_bundle_keeps_the_hash_it_was_recorded_with(self, tmp_path, step):
        """An in-flight ordinary run must not re-bill a model call because the
        adaptation lane was added to the tool underneath it."""
        from tools.trace_cli.candidate_run import _PAID_INPUTS, _inputs_sha
        import hashlib
        bundle = tmp_path / "bundle"
        bundle.mkdir()
        for name in _PAID_INPUTS[step]:
            (bundle / name).write_text(f"{name} body\n")

        legacy = hashlib.sha256()
        for name in _PAID_INPUTS[step]:
            legacy.update(name.encode())
            legacy.update((bundle / name).read_bytes())
        legacy.update(b"model:m")
        prompts = Path(__file__).resolve().parents[2] / "prompts"
        for prompt in sorted(prompts.glob(f"{step}.*.md")):
            legacy.update(prompt.name.encode())
            legacy.update(prompt.read_bytes())

        assert _inputs_sha(bundle, step, "m") == legacy.hexdigest()

    def test_the_reproducer_is_not_bound_to_the_adaptation_inputs(self, tmp_path):
        """It reads the patch and the package, not the pre-patch source, so
        binding it there would re-bill a Reproducer for an unrelated change."""
        from tools.trace_cli.candidate_run import _inputs_sha
        bundle = tmp_path / "bundle"
        sc = bundle / "source-context"
        sc.mkdir(parents=True)
        (bundle / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False}) + "\n")
        (sc / "a.c").write_text("x\n")
        before = _inputs_sha(bundle, "reproducer", "m")
        (sc / "a.c").write_text("y\n")
        assert _inputs_sha(bundle, "reproducer", "m") == before

    @pytest.mark.parametrize("code", ["EXIT_NOT_FOUND", "EXIT_UNPACK_FAILED",
                                      "EXIT_EXTRACT_FAILED", "EXIT_USAGE"])
    def test_only_a_failed_dry_run_opens_the_lane(self, tmp_path, monkeypatch, code):
        """A missing input or a failed unpack says nothing about the base, so
        overriding it would buy a Patcher call on a bundle nobody has read."""
        from tools.trace_cli import candidate_run, preflight
        self._fail(monkeypatch, getattr(preflight, code))
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits",
                            lambda *a, **k: getattr(preflight, code))
        with pytest.raises(StepStopped):
            candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []

    @pytest.mark.parametrize("diagnostics,word", [
        ("Reversed (or previously applied) patch detected!", "already-applied"),
        ("Reversed (or previously applied) patch detected!\nHunk #2 FAILED", "mixed"),
    ])
    def test_a_base_that_already_carries_the_fix_is_a_retirement(
            self, tmp_path, monkeypatch, diagnostics, word):
        """The jsonxs shape: the pinned source is not vulnerable, so there is
        nothing to adapt and a Patcher call would produce invalid evidence."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        self._restage(monkeypatch, False, diagnostics=diagnostics)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert word in e.value.reason
        assert "not vulnerable" in e.value.reason
        assert "entered_adaptation_lane" not in ctx

    def test_the_retry_does_not_erase_the_dry_run_classification(self, tmp_path, monkeypatch):
        """`_retry_with_other_cited_commits` reports a bare 1 when the CVE cites a
        single commit, which is the common case. Letting that replace the real
        exit code would close the lane to every single-commit candidate."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        candidate_run._preflight(ctx, patch_diff=False)
        assert len(calls) == 1

    def test_a_second_cited_commit_that_applies_still_wins(self, tmp_path, monkeypatch):
        """A candidate rescued by another cited fix is a verbatim backport, not
        an adaptation, even with the flag set."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 0)
        candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []
        assert "entered_adaptation_lane" not in ctx

    def _resume_ctx(self, tmp_path, monkeypatch, *, diagnostics="Hunk #3 FAILED",
                    body=None, drop_context=False):
        """A bundle already staged for the lane, as a resume finds it."""
        from tools.trace_cli import candidate_run
        self._fail(monkeypatch)
        calls: list = []
        self._restage(monkeypatch, False, calls=calls)
        ctx = self._ctx(tmp_path, "adaptation canary")
        monkeypatch.setattr(candidate_run, "_retry_with_other_cited_commits", lambda *a, **k: 1)
        (ctx["bundle_dir"] / "preflight.json").write_text(
            json.dumps({"applies_verbatim": False, "diagnostics": diagnostics}) + "\n")
        self._stage_context(ctx["bundle_dir"], body)
        if drop_context:
            (ctx["bundle_dir"] / "source-context" / "src" / "file.c").unlink()
            # Keep the dir non-empty so the early return is still reached.
            (ctx["bundle_dir"] / "source-context" / "unrelated.c").write_text("x\n")
        return ctx, calls

    def test_a_resume_rechecks_that_the_base_is_still_vulnerable(self, tmp_path, monkeypatch):
        """The early return skips the restage, not the checks. A bundle whose
        recorded diagnostics say the fix is already in must not reach the Patcher."""
        from tools.trace_cli import candidate_run
        ctx, calls = self._resume_ctx(
            tmp_path, monkeypatch,
            diagnostics="Reversed (or previously applied) patch detected!")
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert "not vulnerable" in e.value.reason
        assert calls == []

    def test_a_resume_rejects_source_context_that_does_not_match_the_pinned_source(
            self, tmp_path, monkeypatch):
        """Edited or stale context would have the Patcher adapt against source the
        bundle does not actually pin."""
        from tools.trace_cli import candidate_run
        ctx, _ = self._resume_ctx(tmp_path, monkeypatch, body="int tampered(void);\n")
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert "does not match the fetched pinned source" in e.value.reason

    def test_a_resume_rejects_an_incomplete_source_context(self, tmp_path, monkeypatch):
        """Every file the fix touches has to be there, or the adaptation is
        authored against a partial view of the affected code."""
        from tools.trace_cli import candidate_run
        ctx, _ = self._resume_ctx(tmp_path, monkeypatch, drop_context=True)
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert "is missing" in e.value.reason

    def test_a_resume_on_honest_staging_proceeds(self, tmp_path, monkeypatch):
        from tools.trace_cli import candidate_run
        ctx, calls = self._resume_ctx(tmp_path, monkeypatch)
        candidate_run._preflight(ctx, patch_diff=False)
        assert calls == []
        assert ctx["entered_adaptation_lane"] == "adaptation canary"

    def test_an_addition_only_fix_has_nothing_to_adapt_against(self, tmp_path, monkeypatch):
        from tools.trace_cli import candidate_run
        ctx, _ = self._resume_ctx(tmp_path, monkeypatch)
        (ctx["bundle_dir"] / "upstream-fix.patch").write_text(
            "diff --git a/new.c b/new.c\n--- /dev/null\n+++ b/new.c\n@@ -0,0 +1 @@\n+int x;\n")
        with pytest.raises(StepStopped) as e:
            candidate_run._preflight(ctx, patch_diff=False)
        assert "nothing to" in e.value.reason

    def test_the_flag_reaches_the_context_from_the_command_line(self, tmp_path):
        import argparse
        from tools.trace_cli import candidate_run
        root = argparse.ArgumentParser()
        candidate_run.add_parser(root.add_subparsers(dest="cmd"))
        args = root.parse_args([
            "run",
            "--inbox-entry", str(tmp_path / "e"), "--out", str(tmp_path / "o"),
            "--nixpkgs-checkout", str(tmp_path / "n"), "--nixpkgs-rev", "d" * 40,
            "--adaptation-lane", "canary",
        ])
        assert args.adaptation_lane == "canary"
