"""`trace candidate run`: one screened candidate through every gate, in order.

Twelve hand invocations took wget CVE-2026-16599 from a screen entry to a
certifiable bundle. This sequences the same commands with the same refusals and
stops at the first one. It adds no logic of its own: every step is an existing
function, and the only new artifact is `run.jsonl`, one line per step attempted.

Model spend sits behind the free gates by construction: the Patcher, Reviewer
and Reproducer are steps 6, 8 and 9 of eleven, and each earlier step has to pass.

See docs/specs/candidate-orchestrator.md.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

EXIT_READY = 0
EXIT_GATE_STOPPED = 3
EXIT_INFRA = 4
EXIT_STEP_ERROR = 5

PAID_STEPS = frozenset({"patcher", "reviewer", "reproducer"})
Step = Callable[[dict[str, Any]], Any]


class StepStopped(Exception):
    """A gate refused the candidate. `gate` names it, `reason` says why."""

    def __init__(self, gate: str, reason: str):
        super().__init__(reason)
        self.gate = gate
        self.reason = reason


@dataclass
class Steps:
    bootstrap: Step
    assemble: Step
    finalize: Step
    fetch_source: Step
    preflight_upstream: Step
    patcher: Step
    preflight_payload: Step
    reviewer: Step
    reproducer: Step
    probe: Step
    refinalize: Step


ORDER = [f.name for f in fields(Steps)]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(record_path: Path, entry: dict[str, Any]) -> None:
    record_path.parent.mkdir(parents=True, exist_ok=True)
    with record_path.open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _completed_steps(record_path: Path) -> dict[str, dict]:
    """Steps recorded ok in the latest run in this directory.

    Runs are separated by `result` lines. Only the segment after the last result
    line counts, whatever that result was: a run that stopped at the probe has
    completed everything before it, and resuming from the probe is the point.
    """
    if not record_path.is_file():
        return {}
    finished: dict[str, dict] = {}   # the last run that reached a result line
    current: dict[str, dict] = {}    # a run still in progress, or one that crashed
    for line in record_path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("step") == "result":
            finished, current = current, {}
            continue
        if entry.get("status") in ("ok", "skipped"):
            current[entry["step"]] = entry
    return current or finished


# Model outputs on disk mean the model already ran; resume never calls it again,
# provided the inputs that produced the output are unchanged.
_PAID_OUTPUTS = {"patcher": "patch.diff", "reviewer": "review.md", "reproducer": "reproducer.nix"}
_PAID_INPUTS = {
    "patcher": ("package.nix", "upstream-fix.patch", "finding.json", "upstream-ref.json"),
    "reviewer": ("patch.diff", "patch-rationale.md", "package.nix", "upstream-fix.patch"),
    "reproducer": ("patch.diff", "package.nix", "finding.json", "upstream-ref.json"),
}
# On the adaptation lane the Patcher runs patcher.v4 and the Reviewer reads the
# same pinned source it adapted against, so both roles' outputs depend on
# preflight.json and every source-context/ file. Absent here, a resume would
# reuse a patch.diff authored against source that has since changed.
_ADAPTATION_INPUTS = frozenset({"patcher", "reviewer"})
# Free gates are re-run on every resume. A run.jsonl line is a claim, and these
# are the checks that stand between a model payload and a cert.
_ALWAYS_RUN = frozenset({"preflight_upstream", "preflight_payload", "probe", "refinalize"})


def _inputs_sha(bundle_dir: Path, step: str, model_id: str | None = None) -> str:
    """Hash of everything that determines a paid step's output: the bundle files
    it reads, the model it was asked for, and every prompt file for its role.
    A prompt fix or a model bump therefore never reuses an older output."""
    import hashlib

    h = hashlib.sha256()
    for name in _PAID_INPUTS.get(step, ()):
        f = bundle_dir / name
        h.update(name.encode())
        h.update(f.read_bytes() if f.is_file() else b"<absent>")
    pf = bundle_dir / "preflight.json"
    if step in _ADAPTATION_INPUTS and pf.is_file():
        # Mixed in only for a bundle that actually carries them. A verbatim
        # bundle keeps the hash it was recorded with, or every in-flight resume
        # would re-bill a model call it already paid for.
        h.update(b"preflight.json")
        h.update(pf.read_bytes())
        sc = bundle_dir / "source-context"
        for f in sorted(q for q in sc.rglob("*") if q.is_file()) if sc.is_dir() else ():
            h.update(f.relative_to(bundle_dir).as_posix().encode())
            h.update(f.read_bytes())
    h.update(b"model:" + (model_id or "").encode())
    prompts = Path(__file__).resolve().parents[2] / "prompts"
    for prompt in sorted(prompts.glob(f"{step}.*.md")):
        h.update(prompt.name.encode())
        h.update(prompt.read_bytes())
    return h.hexdigest()


def _has_content(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir())


def _recorded_source_tree(recorded: dict[str, dict]) -> Path | None:
    """The source tree a previous fetch_source left, if it is still there.

    A fetchFromGitHub source is already a tree, so extraction leaves out/src empty
    and the tree is the store path itself. The record carries that path; when it
    has gone, the fetch has to run again.
    """
    raw = (recorded.get("fetch_source") or {}).get("source_tree")
    if raw and _has_content(Path(raw)):
        return Path(raw)
    return None


def _rehydrate(ctx: dict[str, Any]) -> None:
    """Fill the ctx keys earlier steps would have set, from the out dir.

    A skipped step ran in a previous process, so its side effects are gone. The
    paths it produced are functions of the out dir; the attr and cve come from the
    bundle it wrote.
    """
    out = Path(ctx["out_dir"])
    ctx.setdefault("staged", out / "staged")
    ctx.setdefault("bundle_dir", out / "bundle")
    src = out / "src"
    if "source_tree" not in ctx and _has_content(src):
        children = [c for c in src.iterdir() if c.is_dir()]
        ctx["source_tree"] = children[0] if len(children) == 1 else src
    finding = ctx["bundle_dir"] / "finding.json"
    if finding.is_file():
        try:
            data = json.loads(finding.read_text())
            ctx.setdefault("cve_id", data.get("cve_id"))
            affected = data.get("affected") or [{}]
            ctx.setdefault("attr_path", affected[0].get("attr_path"))
        except json.JSONDecodeError:
            pass


def run_candidate(ctx: dict[str, Any], *, steps: Steps, resume: bool = False,
                  until: str | None = None) -> int:
    """Run the steps in order. Returns EXIT_READY, EXIT_GATE_STOPPED, EXIT_INFRA or EXIT_STEP_ERROR.

    `until` names the last step to run, for surveying candidates through the free
    gates without reaching a paid step.
    """
    from tools.trace_cli.execute import ExecutionError

    if until is not None and until not in ORDER:
        raise ValueError(f"unknown step {until!r}; one of {ORDER}")

    out_dir = Path(ctx["out_dir"])
    record = out_dir / "run.jsonl"
    skip: set[str] = set()
    recorded: dict[str, dict] = {}
    if resume:
        bundle_dir = out_dir / "bundle"
        recorded = _completed_steps(record)
        for name in ORDER:
            if name in _ALWAYS_RUN or name not in recorded:
                continue
            if name in PAID_STEPS:
                # Reuse a model output only if it exists and its inputs are unchanged.
                if not (bundle_dir / _PAID_OUTPUTS[name]).is_file():
                    continue
                if recorded[name].get("inputs_sha256") != _inputs_sha(
                        bundle_dir, name, ctx.get("models", {}).get(name)):
                    continue
            if name == "fetch_source":
                tree = _recorded_source_tree(recorded)
                if tree is None and not _has_content(out_dir / "src"):
                    continue
                if tree is not None:
                    ctx["source_tree"] = tree
            skip.add(name)
        _rehydrate(ctx)

    def stop(name: str, reason: str) -> int:
        _append(record, {"at": _now(), "step": name, "status": "stopped", "reason": reason})
        _append(record, {"at": _now(), "step": "result", "outcome": "stopped", "gate": name, "reason": reason})
        return EXIT_GATE_STOPPED

    for name in ORDER:
        if name in skip:
            entry = {"at": _now(), "step": name, "status": "skipped", "reason": "resume"}
            if name in PAID_STEPS:
                # Carry the hash forward, or a resume of a resume would re-bill.
                entry["inputs_sha256"] = recorded[name].get("inputs_sha256")
            _append(record, entry)
            continue
        step: Step = getattr(steps, name)
        try:
            result = step(ctx)
        except StepStopped as gate:
            return stop(name, gate.reason)
        except SystemExit as exit_:
            # A wrapped command that exits the process is treated as its refusal.
            # Exit 0 would mean success and is not a stop.
            if exit_.code in (0, None):
                result = None
            else:
                return stop(name, f"{name} exited with status {exit_.code}")
        except ExecutionError as contract:
            _append(record, {"at": _now(), "step": name, "status": "error", "reason": str(contract)})
            _append(record, {"at": _now(), "step": "result", "outcome": "step-error",
                             "step_failed": name, "reason": str(contract)})
            return EXIT_STEP_ERROR
        except (OSError, subprocess.SubprocessError, RuntimeError) as infra:
            _append(record, {"at": _now(), "step": name, "status": "error", "reason": str(infra)})
            _append(record, {"at": _now(), "step": "result", "outcome": "infrastructure-error",
                             "reason": str(infra)})
            return EXIT_INFRA
        except Exception as bug:  # noqa: BLE001 - a bug in a step is recorded, then surfaced
            reason = f"{type(bug).__name__}: {bug}"
            _append(record, {"at": _now(), "step": name, "status": "error", "reason": reason})
            _append(record, {"at": _now(), "step": "result", "outcome": "step-error",
                             "step_failed": name, "reason": reason})
            return EXIT_STEP_ERROR
        # Two steps carry their verdict in the return value rather than raising.
        if name == "reviewer" and result not in (None, "accept"):
            return stop(name, f"reviewer verdict {result}")
        if name == "probe" and result is False:
            return stop(name, "fixture does not discriminate")
        ctx.setdefault("results", {})[name] = result
        entry = {"at": _now(), "step": name, "status": "ok"}
        if name == "preflight_upstream" and ctx.get("entered_adaptation_lane"):
            entry["adaptation_lane"] = ctx["entered_adaptation_lane"]
        if name == "fetch_source" and result is not None:
            ctx["source_tree"] = Path(result)
            entry["source_tree"] = str(result)
        if name in PAID_STEPS:
            entry["inputs_sha256"] = _inputs_sha(
                Path(ctx.get("bundle_dir") or out_dir / "bundle"), name, ctx.get("models", {}).get(name))
        _append(record, entry)
        if until == name:
            _append(record, {"at": _now(), "step": "result", "outcome": "stopped-at-until", "until": name})
            return EXIT_READY

    _append(record, {"at": _now(), "step": "result", "outcome": "ready-for-cert"})
    return EXIT_READY


# ─── the real steps ────────────────────────────────────────────────────────────


def _kind_args(ctx: dict[str, Any]) -> dict[str, Any]:
    return {
        "bundle_kind": "human-review-required",
        "kind_reason": "source-backport-experimental",
        "created_at": ctx["created_at"],
    }


def _bootstrap(ctx: dict[str, Any]) -> None:
    from tools.trace_cli.bootstrap import BootstrapError, bootstrap_candidate

    staged = Path(ctx["out_dir"]) / "staged"
    try:
        result = bootstrap_candidate(
            entry_dir=Path(ctx["inbox_entry"]), out_dir=staged,
            nixpkgs_checkout=Path(ctx["nixpkgs_checkout"]), nixpkgs_rev=ctx["nixpkgs_rev"],
            package_path=ctx.get("package_path"), force=True,
        )
    except BootstrapError as e:
        raise StepStopped("bootstrap", str(e)) from e
    ctx["staged"] = staged
    ctx["attr_path"] = result.attr_path
    ctx["cve_id"] = result.cve_id


def _assemble(ctx: dict[str, Any]) -> None:
    from tools.trace_cli.bundle import assemble_bundle

    staged: Path = ctx["staged"]
    bundle_dir = Path(ctx["out_dir"]) / "bundle"
    try:
        assemble_bundle(
            resolver_input_path=staged / "resolver-input.json",
            package_nix_path=staged / "package.nix",
            finding_path=staged / "finding.json",
            impact_path=staged / "impact.json",
            maintainers_path=staged / "maintainers.json",
            upstream_fix_patch_path=staged / "upstream-fix.patch",
            attr_path=ctx["attr_path"], nixpkgs_rev=ctx["nixpkgs_rev"], out_dir=bundle_dir,
        )
    except (ValueError, KeyError) as e:
        raise StepStopped("assemble", f"assemble refused: {e}") from e
    ctx["bundle_dir"] = bundle_dir


def _finalize(ctx: dict[str, Any]) -> None:
    from tools.trace_cli.bundle import finalize_bundle

    try:
        finalize_bundle(bundle_dir=ctx["bundle_dir"], **_kind_args(ctx))
    except (ValueError, KeyError) as e:
        raise StepStopped("finalize", f"finalize refused: {e}") from e


def _fetch_source(ctx: dict[str, Any]) -> Path:
    """Materialise the pinned source under out/src. Network and store failures are
    infrastructure, not a verdict about the candidate."""
    from tools.trace_cli.pinned_source import _build_pinned_src, unpack_source_store_path

    tmp_root = Path(ctx["out_dir"]) / "src-tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    store_path, *_ = _build_pinned_src(ctx["bundle_dir"], tmp_root, None)
    dest = Path(ctx["out_dir"]) / "src"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    tree = unpack_source_store_path(store_path, dest)
    ctx["source_tree"] = tree
    return tree


def _choose_applying_fix(commits: list[dict], *, fetch_patch, applies) -> tuple[dict, str] | None:
    """The first cited fix commit whose patch applies to the pinned source.

    A CVE record often cites one fix commit per maintained branch. Bootstrap takes
    the first, which may be the backport to an older line; svgo CVE-2026-84370
    cited the v2, v3 and v4 fixes and nixpkgs packages 4.0.1. Each candidate is
    fetched and tried in the order cited.
    """
    from tools.trace_cli.bootstrap import commit_patch_url

    for commit in commits:
        url = commit_patch_url(commit.get("repo_url", ""), commit.get("commit_sha", ""))
        try:
            text = fetch_patch(url)
        except Exception:  # noqa: BLE001 - an unfetchable candidate is skipped, not fatal
            continue
        if text and applies(text):
            return commit, text
    return None


def _preflight(ctx: dict[str, Any], *, patch_diff: bool) -> None:
    from tools.trace_cli import preflight

    args = argparse.Namespace(
        bundle_dir=ctx["bundle_dir"], source_tree=ctx["source_tree"], patches=[],
        strip=None, patch_flags=None, patch_diff=patch_diff, format="human",
    )
    repo_root = Path(__file__).resolve().parents[2]
    code = preflight.run(args, repo_root=repo_root)
    if code != 0 and not patch_diff:
        # The retry reports a bare 1 when it has nothing to try, which would erase
        # the dry-run classification the adaptation lane keys on. Only a success
        # replaces the original verdict.
        retried = _retry_with_other_cited_commits(ctx, args, repo_root)
        if retried == 0:
            code = 0
    if code == 0:
        return
    if not patch_diff and _adaptation_reason(ctx) and code == preflight.EXIT_APPLY_FAILED:
        # Only a failed dry-run can be an adaptation. A missing input, a source
        # tree that would not extract or a usage error is infrastructure, and
        # overriding those buys a Patcher call on a base nobody has read.
        _enter_adaptation_lane(ctx)
        return
    which = "the model payload" if patch_diff else "upstream-fix.patch"
    raise StepStopped("preflight_payload" if patch_diff else "preflight_upstream",
                      f"{which} does not apply to the pinned source (preflight exit {code})")


def _adaptation_reason(ctx: dict[str, Any]) -> str:
    """The operator's stated reason for continuing past a base mismatch.

    Empty unless `--adaptation-lane` was passed with non-whitespace text.
    """
    raw = ctx.get("adaptation_lane")
    return raw.strip() if isinstance(raw, str) else ""


def _enter_adaptation_lane(ctx: dict[str, Any]) -> None:
    """Restage the bundle against the fetched pinned source, then refinalize.

    A failing upstream preflight is the adaptation lane's normal state: the fix is
    expressible on the pinned base but not verbatim. Continuing is only meaningful
    if the Patcher is actually routed to patcher.v4, and that routing is driven by
    `source-context/` plus `preflight.json.applies_verbatim`, which only the
    source-backport staging writes. Restaging with the tree fetched two steps
    earlier produces both, and finalize then hashes them into the signed manifest
    as replay-critical inputs, so the mismatch cannot be edited away afterwards.
    Assembling without a tree, as the first pass did, leaves neither, and the run
    would reach the Patcher on the verbatim v3 prompt with nothing recording that
    the base had diverged.
    """
    from tools.trace_cli.bundle import assemble_bundle
    from tools.trace_cli.source_context import SourceContextError

    if _already_staged_for_adaptation(ctx["bundle_dir"]):
        # preflight_upstream re-runs on every resume, and assemble rewrites
        # replay.json as a resolver-only seed. Restaging a bundle that is already
        # on the adaptation lane would therefore drop the Patcher, Reviewer and
        # Reproducer invocations while their outputs stayed on disk, leaving
        # artifacts no replay record accounts for. The staging still gets checked:
        # skipping the restage is not the same as trusting what is on disk.
        _assert_adaptation_staging(ctx)
        ctx["entered_adaptation_lane"] = _adaptation_reason(ctx)
        return

    present = sorted(name for name, out in _PAID_OUTPUTS.items()
                     if (Path(ctx["bundle_dir"]) / out).is_file())
    if present:
        # Restaging rewrites replay.json as a resolver-only seed. A resume decides
        # what to skip from hashes taken before that, so these outputs would stay
        # on disk with no invocation recording what produced them. Reached when a
        # bundle already carrying model outputs is switched onto the lane; the
        # honest repair is a clean run, not a silently unverifiable bundle.
        raise StepStopped(
            "preflight_upstream",
            "cannot switch to the adaptation lane on a bundle that already carries "
            f"model output ({', '.join(_PAID_OUTPUTS[n] for n in present)}): restaging "
            "would reset replay.json and orphan them. Start a fresh --out.",
        )

    staged: Path = ctx["staged"]
    try:
        assemble_bundle(
            resolver_input_path=staged / "resolver-input.json",
            package_nix_path=staged / "package.nix",
            finding_path=staged / "finding.json",
            impact_path=staged / "impact.json",
            maintainers_path=staged / "maintainers.json",
            upstream_fix_patch_path=staged / "upstream-fix.patch",
            attr_path=ctx["attr_path"], nixpkgs_rev=ctx["nixpkgs_rev"],
            out_dir=ctx["bundle_dir"], source_tree=Path(ctx["source_tree"]),
        )
    except SourceContextError as e:
        # A file the fix touches is missing from the pinned source. That is the
        # libarchive shape, where no faithful backport exists, and no operator
        # reason makes it adaptable.
        raise StepStopped("preflight_upstream",
                          f"the fix touches source absent from the pinned base: {e}") from e
    except (ValueError, KeyError) as e:
        raise StepStopped("preflight_upstream", f"adaptation restage refused: {e}") from e

    _finalize(ctx)

    _assert_adaptation_staging(ctx)
    ctx["entered_adaptation_lane"] = _adaptation_reason(ctx)


def _assert_adaptation_staging(ctx: dict[str, Any]) -> None:
    """Refuse to reach the Patcher unless the staged lane is honest.

    Three things have to hold, and a bundle on disk is a claim about none of
    them: the verdict says the fix does not apply verbatim, the reason is a real
    dry-run failure rather than a base that already carries the fix, and the
    source the Patcher will adapt against is the whole affected file set, byte
    for byte, from the source that was actually fetched.
    """
    from tools.trace_cli import preflight as preflight_mod
    from tools.trace_cli import source_context

    bundle_dir = Path(ctx["bundle_dir"])
    pf = bundle_dir / "preflight.json"
    try:
        doc = json.loads(pf.read_text()) if pf.is_file() else {}
    except json.JSONDecodeError:
        doc = {}
    if doc.get("applies_verbatim") is not False:
        raise StepStopped(
            "preflight_upstream",
            "staged for the adaptation lane but preflight.json does not record "
            "applies_verbatim false; refusing to reach the Patcher on an unrecorded base",
        )
    disposition = preflight_mod.classify_patch_output(doc.get("diagnostics") or "")
    if disposition != "does-not-apply":
        # The pinned source already carries the change, so there is nothing to
        # adapt and nothing to fix. The jsonxs shape: retire, do not re-pin.
        raise StepStopped(
            "preflight_upstream",
            f"the upstream fix reads as {disposition} against the pinned source, "
            "so the pinned base is not vulnerable; this is a retirement, not an adaptation",
        )

    fix = bundle_dir / "upstream-fix.patch"
    if not fix.is_file():
        raise StepStopped("preflight_upstream",
                          "no upstream-fix.patch to adapt from; refusing the lane")
    touched = source_context.parse_touched_paths(fix.read_text())
    if not touched:
        raise StepStopped(
            "preflight_upstream",
            "the upstream fix touches no pre-patch file, so there is nothing to "
            "adapt against; this is the verbatim lane",
        )
    tree = Path(ctx["source_tree"])
    sc = bundle_dir / "source-context"
    for rel in touched:
        staged_file = sc / rel
        pinned = tree / rel
        if not staged_file.is_file():
            raise StepStopped(
                "preflight_upstream",
                f"source-context/{rel} is missing, so the Patcher would adapt "
                "against an incomplete view of the affected source",
            )
        if not pinned.is_file() or staged_file.read_bytes() != pinned.read_bytes():
            raise StepStopped(
                "preflight_upstream",
                f"source-context/{rel} does not match the fetched pinned source; "
                "the staged lane is stale or edited",
            )


def _already_staged_for_adaptation(bundle_dir: Path) -> bool:
    """True when this bundle already carries the adaptation lane's staged inputs.

    Both halves must be there: the signed `applies_verbatim: false` verdict and at
    least one `source-context/` file for the Patcher to adapt against. A bundle
    with one and not the other is not on the lane and gets restaged.
    """
    pf = bundle_dir / "preflight.json"
    if not pf.is_file():
        return False
    try:
        verdict = json.loads(pf.read_text()).get("applies_verbatim")
    except json.JSONDecodeError:
        return False
    if verdict is not False:
        return False
    sc = bundle_dir / "source-context"
    return sc.is_dir() and any(f.is_file() for f in sc.rglob("*"))


def _retry_with_other_cited_commits(ctx: dict[str, Any], args: argparse.Namespace, repo_root: Path) -> int:
    """When the first cited fix does not apply, try the others the CVE names."""
    import shutil as _shutil

    from tools.trace_cli import preflight
    from tools.trace_cli.bootstrap import fetch_patch

    bundle_dir: Path = ctx["bundle_dir"]
    ref_path = bundle_dir / "upstream-ref.json"
    if not ref_path.is_file():
        return 1
    ref = json.loads(ref_path.read_text())
    commits = ref.get("upstream_fix_commits") or []
    if len(commits) < 2:
        return 1
    original = (bundle_dir / "upstream-fix.patch").read_text()

    def applies(text: str) -> bool:
        (bundle_dir / "upstream-fix.patch").write_text(text)
        return preflight.run(args, repo_root=repo_root) == 0

    chosen = _choose_applying_fix(commits[1:], fetch_patch=fetch_patch, applies=applies)
    if chosen is None:
        (bundle_dir / "upstream-fix.patch").write_text(original)
        return 1
    commit, _text = chosen
    # Put the commit that applies first so the Patcher and the record agree on the fix.
    ref["upstream_fix_commits"] = [commit] + [c for c in commits if c is not commit]
    ref_path.write_text(json.dumps(ref, indent=2) + "\n")
    ctx.setdefault("notes", []).append(
        f"upstream fix: cited commit {commits[0].get('commit_sha', '')[:12]} did not apply; "
        f"using {commit.get('commit_sha', '')[:12]}, which does")
    return 0


def _role(ctx: dict[str, Any], role: str) -> dict[str, Any]:
    from tools.trace_cli.execute import execute

    invocation = {"invocation_id": None, "inputs": [], "outputs": []}
    return execute(role, ctx["bundle_dir"], invocation, verify=True,
                   model_id=ctx["models"][role], adapter_factory=ctx.get("adapter_factory"))


def _patcher(ctx: dict[str, Any]) -> None:
    result = _role(ctx, "patcher")
    if (ctx["bundle_dir"] / "refusal.json").is_file():
        raise StepStopped("patcher", "the Patcher refused; see refusal.json")
    ctx.setdefault("invocations", {})["patcher"] = result


def _reviewer(ctx: dict[str, Any]) -> str:
    _role(ctx, "reviewer")
    review = ctx["bundle_dir"] / "review.md"
    if not review.is_file():
        return "refused"
    text = review.read_text()
    marker = "## Verdict"
    if marker not in text:
        return "malformed"
    after = text.split(marker, 1)[1].strip().splitlines()
    return after[0].strip().lower() if after else "malformed"


def _reproducer(ctx: dict[str, Any]) -> None:
    _role(ctx, "reproducer")
    if not (ctx["bundle_dir"] / "reproducer.nix").is_file():
        raise StepStopped("reproducer", "the Reproducer produced no fixture; see reproducer-refusal.json")


def _probe(ctx: dict[str, Any]) -> bool:
    from agents.builder import LocalNixBuildRunner
    from tools.trace_cli.probe import EXIT_OK, EXIT_PROBE_ERROR, ProbeRefused, probe_bundle

    try:
        code, verdict = probe_bundle(
            ctx["bundle_dir"], build_runner=ctx.get("build_runner") or LocalNixBuildRunner(),
            nixpkgs_checkout=Path(ctx["nixpkgs_checkout"]),
        )
    except ProbeRefused as e:
        raise StepStopped("probe", str(e)) from e
    if code == EXIT_PROBE_ERROR:
        raise RuntimeError(f"probe could not run: {verdict.get('error')}")
    # The exit code, not `discriminates` alone: an arm can carry its SIGNAL over a
    # run that never happened, and the probe folds that into its status.
    return code == EXIT_OK


def _refinalize(ctx: dict[str, Any]) -> None:
    _finalize(ctx)


def default_steps() -> Steps:
    return Steps(
        bootstrap=_bootstrap, assemble=_assemble, finalize=_finalize,
        fetch_source=_fetch_source, preflight_upstream=lambda c: _preflight(c, patch_diff=False),
        patcher=_patcher, preflight_payload=lambda c: _preflight(c, patch_diff=True),
        reviewer=_reviewer, reproducer=_reproducer, probe=_probe, refinalize=_refinalize,
    )


def add_parser(subs: argparse._SubParsersAction) -> None:
    p = subs.add_parser(
        "run",
        help="take one screened candidate through every gate, stopping at the first refusal",
        description=(
            "bootstrap, assemble, finalize, fetch the pinned source, preflight the upstream "
            "patch, Patcher, preflight the payload, Reviewer, Reproducer, probe, finalize. "
            "Each step appends one line to <out>/run.jsonl. Model spend happens only after "
            "every free gate ahead of it has passed."
        ),
    )
    p.add_argument("--inbox-entry", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--nixpkgs-checkout", type=Path, required=True,
                   help="clean git checkout at --nixpkgs-rev; the probe resets it to HEAD")
    p.add_argument("--nixpkgs-rev", required=True)
    p.add_argument("--package-path", default=None)
    p.add_argument("--created-at", default=None, help="bundle created_at (default: now)")
    p.add_argument("--patcher-model", default="claude-opus-4-7")
    p.add_argument("--reviewer-model", default="claude-sonnet-4-5-20250929")
    p.add_argument("--reproducer-model", default="claude-sonnet-4-5-20250929")
    p.add_argument("--until", default=None, choices=ORDER,
                   help="run through this step and stop; use it to survey the free gates without spend")
    p.add_argument("--resume", action="store_true",
                   help="skip steps the last run in --out completed; never repeats a model call")
    p.add_argument("--adaptation-lane", default=None, metavar="REASON",
                   help="continue past a failing upstream-patch preflight by restaging the "
                        "bundle against the fetched pinned source, which routes the Patcher to "
                        "patcher.v4 and signs the applies_verbatim verdict. For the "
                        "semantic-adaptation lane, where the fix is expressible on the pinned "
                        "base but does not apply verbatim. REASON is recorded in run.jsonl. The "
                        "payload preflight still gates.")


def run(args: argparse.Namespace) -> int:
    ctx = {
        "inbox_entry": args.inbox_entry, "out_dir": args.out,
        "nixpkgs_checkout": args.nixpkgs_checkout, "nixpkgs_rev": args.nixpkgs_rev,
        "package_path": args.package_path,
        "created_at": args.created_at or _now(),
        "models": {"patcher": args.patcher_model, "reviewer": args.reviewer_model,
                   "reproducer": args.reproducer_model},
        "adaptation_lane": args.adaptation_lane,
    }
    code = run_candidate(ctx, steps=default_steps(), resume=args.resume, until=args.until)
    last = (Path(args.out) / "run.jsonl").read_text().splitlines()[-1]
    print(last)
    return code
