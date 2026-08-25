"""`trace reproducer sample` — verifier-guided pass@K for the Reproducer.

Drives `agents.reproducer.sampling.sample_reproducer` against a finalized
bundle: assembles the same inputs the single-shot Reproducer reads, enforces
the cross-family rule, samples K candidates, screens each through the real
two-arm Builder, and — on the first candidate whose unpatched arm emits
SIGNAL_UNPATCHED and whose patched arm emits SIGNAL_PATCHED — commits the
winner into the bundle and writes a `reproducer-sampling.json` provenance
sidecar. When no draw discriminates, it writes the sidecar and routes the
bundle to human-review without touching the reproducer files.

The local Builder run is a SCREEN, not the authority: the winner still has to
pass a clean CI cert (`bundle-linux-cert.yml`). The sidecar records enough to
reconstruct the sample (model, prompt hash, per-draw temperature and verdict,
which draw won) and to escalate later.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

SAMPLING_SIDECAR_SCHEMA_VERSION = 1

# Model-id prefixes whose adapter drops `temperature` entirely (kept in sync
# with AnthropicAdapter._MODELS_DROP_SAMPLING). Sampling these gives K identical
# draws, so pass@K is pointless spend AND the recorded temperatures would be a
# fiction. Reject them up front. (fable-5 also refuses this role at its safety
# layer, so it is doubly wrong here.)
_TEMPERATURE_IGNORING_PREFIXES = (
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-fable-5",
)

# Exit codes: 0 winner committed, 3 no discriminating draw (route human-review),
# 4 probe infrastructure failed (verifier never ran — retry / escalate to CI),
# 2 usage / dispatch error.
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_WINNER = 3
EXIT_PROBE_INFRA = 4


def add_parser(subs: argparse._SubParsersAction) -> None:
    """Register `trace reproducer sample` on the reproducer subparser."""
    sp = subs.add_parser(
        "sample",
        help=(
            "verifier-guided pass@K: sample K reproducers, screen each through "
            "the two-arm Builder, commit the first that discriminates + write a "
            "reproducer-sampling.json provenance sidecar."
        ),
    )
    sp.add_argument("--bundle", type=Path, required=True,
                    help="bundle directory (finalized: patch.diff + inputs present)")
    sp.add_argument("--model", required=True,
                    help="Reproducer model id (must differ in family from the Patcher)")
    sp.add_argument("--k", type=int, default=4,
                    help="number of candidates to sample (default: 4)")
    sp.add_argument("--nixpkgs-checkout", type=Path, default=None,
                    help="nixpkgs checkout for the Builder's patch-apply. REQUIRED "
                         "for the real local screen: without it the Builder skips "
                         "patch-apply and the patched arm builds against unpatched "
                         "source. Treated as disposable (restored to HEAD per draw).")
    sp.add_argument("--overwrite", action="store_true",
                    help="resample even if the bundle already has a reproducer.nix "
                         "(the existing outputs are quarantined if no draw wins)")
    sp.add_argument("--probe-root", type=Path, default=None,
                    help="scratch dir for per-draw probe workspaces (default: a "
                         "temp dir). Candidate files persist here for CI escalation.")
    sp.add_argument("--exhaustive", action="store_true",
                    help="keep probing all K past the first winner (audit-slice "
                         "pass-rate signal); the winner stays the first green.")
    sp.add_argument("--builder-timeout-seconds", type=int, default=1800,
                    help="per-build timeout passed to the Builder (default: 1800)")


def build_sampling_provenance(
    result: Any,
    *,
    model_id: str,
    prompt_path: str,
    prompt_sha256: str,
    tool_version: str,
    generated_at: str,
    verifier: str,
    exhaustive: bool,
) -> dict[str, Any]:
    """Assemble the reproducer-sampling.json body from a SamplingResult.

    Pure: no IO. The sidecar is the audit record for a verifier-selected
    winner — it must let a reader reconstruct which draw won, at what
    temperature, under which model + prompt, and what every draw's verdict was.
    """
    winner = None
    if result.winner_index is not None:
        wd = next(d for d in result.draws if d.index == result.winner_index)
        winner = {
            "draw_index": wd.index,
            "temperature": wd.temperature,
            "reproducer_nix_sha256": wd.reproducer_nix_sha256,
        }
    return {
        "schema_version": SAMPLING_SIDECAR_SCHEMA_VERSION,
        "generated_at": generated_at,
        "tool_version": tool_version,
        "model_id": model_id,
        "prompt_path": prompt_path,
        "prompt_sha256": prompt_sha256,
        "verifier": verifier,
        "k": result.k,
        "temperatures": list(result.temperatures),
        "exhaustive": exhaustive,
        "discriminating_draws": result.discriminating_draws,
        "winner": winner,
        "draws": [
            {
                "index": d.index,
                "temperature": d.temperature,
                "kind": d.kind,
                "signal_unpatched_present": d.signal_unpatched_present,
                "signal_patched_present": d.signal_patched_present,
                "discriminates": d.discriminates,
                "signal_specificity_ok": d.signal_specificity_ok,
                "reproducer_nix_sha256": d.reproducer_nix_sha256,
                "detail": d.detail,
            }
            for d in result.draws
        ],
    }


def commit_winner(bundle_dir: Path, result: Any) -> list[dict[str, Any]]:
    """Atomic-write the winning candidate's three files into the bundle.

    Returns the output records (path / sha256 / bytes). Raises ValueError if
    there is no winner — the caller must gate on result.winner_index first.
    """
    from tools.trace_cli.execute import _atomic_write_bytes, sha256_hex

    if result.winning_files is None:
        raise ValueError("commit_winner called with no winning candidate")
    outputs: list[dict[str, Any]] = []
    for name in ("reproducer.nix", "reproducer-log.txt", "passthru-tests.json"):
        buf = result.winning_files[name]
        if buf and not buf.endswith(b"\n"):
            buf = buf + b"\n"
        _atomic_write_bytes(bundle_dir / name, buf)
        outputs.append({"path": name, "sha256": sha256_hex(buf), "bytes": len(buf)})
    # A prior Reproducer refusal (resampling a bundle that was routed
    # human-review for lack of a reproducer) must be cleared: run_builder's
    # `has_reproducer` requires reproducer-refusal.json to be ABSENT, so leaving
    # it would make the cert silently ignore this committed winner.
    refusal = bundle_dir / "reproducer-refusal.json"
    if refusal.is_file():
        refusal.unlink()
    return outputs


def _load_inputs(bundle_dir: Path) -> dict[str, Any]:
    """Read the Reproducer inputs the same way the single-shot executor does."""
    from tools.trace_cli.execute import _collect_bundle_local_pocs

    def _req(name: str) -> Path:
        p = bundle_dir / name
        if not p.is_file():
            raise FileNotFoundError(f"reproducer sample requires {name} in the bundle (missing: {p})")
        return p

    finding = json.loads(_req("finding.json").read_text())
    upstream_ref = json.loads(_req("upstream-ref.json").read_text())
    impact = json.loads(_req("impact.json").read_text())
    maintainers = json.loads(_req("maintainers.json").read_text())
    package_path = _req("package.nix")
    diff_path = _req("patch.diff")
    rat_path = _req("patch-rationale.md")
    return {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_path.read_text(),
        "package_source_path": package_path.name,
        "patch_diff": diff_path.read_text(),
        "patch_rationale_md": rat_path.read_text(),
        "bundle_local_pocs": _collect_bundle_local_pocs(bundle_dir),
    }


def run(
    args: argparse.Namespace,
    *,
    _adapter_factory: Callable[[str], Any] | None = None,
    _probe_fn: Callable[..., Any] | None = None,
) -> int:
    """Drive pass@K sampling on args.bundle. Returns an exit code.

    `_adapter_factory` / `_probe_fn` are test seams; production leaves them None
    and builds the real Anthropic adapter + local Builder probe.
    """
    import tempfile

    from agents.reproducer.sampling import build_probe_fn, sample_reproducer
    from tools.trace_cli.execute import (
        REPRODUCER_PROMPT_PATH_DEFAULT,
        _atomic_write_bytes,
        _model_id_family,
        _read_patcher_family_from_replay,
        _utc_now_iso,
        sha256_hex,
    )

    bundle_dir: Path = args.bundle
    if not bundle_dir.is_dir():
        print(f"error: bundle dir not found: {bundle_dir}", flush=True)
        return EXIT_USAGE

    # Dispatch guards mirror the single-shot executor: advisory-only bundles and
    # Patcher refusals have no patch to reproduce.
    bundle_json = bundle_dir / "bundle.json"
    if bundle_json.is_file():
        try:
            if json.loads(bundle_json.read_text()).get("kind") == "advisory-only":
                print("error: bundle is advisory-only; nothing to reproduce", flush=True)
                return EXIT_USAGE
        except json.JSONDecodeError:
            pass
    if (bundle_dir / "refusal.json").is_file():
        print("error: bundle has a Patcher refusal.json; no patch to reproduce", flush=True)
        return EXIT_USAGE

    # Cross-family rule: the Reproducer model must not share the Patcher's family.
    patcher_family = _read_patcher_family_from_replay(bundle_dir)
    requested_family = _model_id_family(args.model)
    if patcher_family and requested_family and patcher_family == requested_family:
        print(
            f"error: model {args.model!r} is in the same family "
            f"({requested_family!r}) as the Patcher; the cross-family rule forbids it",
            flush=True,
        )
        return EXIT_USAGE

    if args.k < 1:
        print(f"error: --k must be >= 1 (got {args.k})", flush=True)
        return EXIT_USAGE

    # pass@K needs a model whose adapter honors the temperature schedule; models
    # that drop temperature give K identical draws (pointless spend).
    if any(args.model.startswith(p) for p in _TEMPERATURE_IGNORING_PREFIXES):
        print(
            f"error: model {args.model!r} ignores temperature, so pass@K would "
            f"draw K identical candidates; pick a model that samples "
            f"(e.g. claude-sonnet-* / claude-haiku-*)",
            flush=True,
        )
        return EXIT_USAGE

    # Don't silently clobber an existing reproducer (analyst-authored or from a
    # prior winning sweep). Resampling requires an explicit --overwrite.
    if (bundle_dir / "reproducer.nix").is_file() and not args.overwrite:
        print(
            "error: bundle already has a reproducer.nix; pass --overwrite to resample "
            "(existing outputs are quarantined if no draw wins)",
            flush=True,
        )
        return EXIT_USAGE

    # Live model calls are research spend and must run against a finalized,
    # replay-backed bundle: without a valid replay.json the cross-family rule
    # silently no-ops (no Patcher family to compare against). Enforce this only
    # for the real path (tests inject a probe and drive minimal bundles).
    if _probe_fn is None:
        err = _validate_finalized_bundle(bundle_dir)
        if err is not None:
            print(f"error: {err}", flush=True)
            return EXIT_USAGE

    # The real local screen needs a usable checkout: run_builder applies
    # patch.diff to it to build the patched arm. Validate it BEFORE any model
    # spend, so a misconfigured checkout exits clean instead of billing K calls
    # that all fail as probe-errors and misreport as no-winner.
    if _probe_fn is None:
        if args.nixpkgs_checkout is None:
            print(
                "error: --nixpkgs-checkout is required for the local screen (the "
                "Builder applies patch.diff to it to build the patched arm)",
                flush=True,
            )
            return EXIT_USAGE
        err = _validate_checkout(args.nixpkgs_checkout, bundle_dir)
        if err is not None:
            print(f"error: {err}", flush=True)
            return EXIT_USAGE

    try:
        inputs = _load_inputs(bundle_dir)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", flush=True)
        return EXIT_USAGE

    prompt_path = REPRODUCER_PROMPT_PATH_DEFAULT
    prompt_sha256 = sha256_hex(prompt_path.read_bytes())

    if _adapter_factory is not None:
        adapter = _adapter_factory(args.model)
    else:
        from tools.trace_cli.execute import _build_adapter_from_model_id
        adapter = _build_adapter_from_model_id(args.model, role_label="reproducer")

    if _probe_fn is not None:
        probe_fn = _probe_fn
    else:
        from agents.builder.protocol import LocalNixBuildRunner
        probe_fn = build_probe_fn(
            bundle_dir=bundle_dir,
            build_runner=LocalNixBuildRunner(),
            nixpkgs_checkout=args.nixpkgs_checkout,
            timeout_seconds_per_build=args.builder_timeout_seconds,
        )

    probe_root = args.probe_root or Path(tempfile.mkdtemp(prefix="trace-repro-sample-"))
    probe_root.mkdir(parents=True, exist_ok=True)

    result = sample_reproducer(
        inputs=inputs,
        adapter=adapter,
        probe_fn=probe_fn,
        prompt_path=prompt_path,
        probe_root=probe_root,
        k=args.k,
        exhaustive=args.exhaustive,
    )

    provenance = build_sampling_provenance(
        result,
        model_id=args.model,
        prompt_path=f"prompts/{prompt_path.name}",
        prompt_sha256=prompt_sha256,
        tool_version=_tool_version(),
        generated_at=_utc_now_iso(),
        verifier="local-screen",
        exhaustive=args.exhaustive,
    )
    sidecar_bytes = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
    canonical_sidecar = bundle_dir / "reproducer-sampling.json"

    if result.winner_index is None:
        # Quarantining an existing reproducer is destructive, so it fires ONLY on
        # a clean, fully-evaluated sweep that found no discriminator. Two things
        # block that: a probe error (some candidate was never evaluated, so the
        # sweep is incomplete and may have missed a discriminator) or no evaluated
        # candidate at all (the model produced nothing testable). Both preserve
        # the existing reproducer. The canonical sidecar describes the reproducer
        # on disk, so a preserving sweep records to a separate attempts file (when
        # a reproducer exists) rather than clobbering its provenance.
        had_probe_error = any(d.kind == "probe-error" for d in result.draws)
        evaluated = any(d.kind == "reproducer" for d in result.draws)

        def _record_preserving() -> str:
            if (bundle_dir / "reproducer.nix").is_file():
                return f"Attempt record: {_write_attempt_record(bundle_dir, sidecar_bytes)}"
            _atomic_write_bytes(canonical_sidecar, sidecar_bytes)
            return f"Sidecar: {canonical_sidecar}"

        if had_probe_error:
            # Incomplete sweep: a probe error means that candidate was never
            # evaluated (nix daemon / store down, a local false negative), so we
            # cannot conclude no fixture discriminates. Preserve, report infra.
            note = _record_preserving()
            print(
                f"probe infrastructure failed on at least one of {result.k} draws; "
                f"incomplete sweep, not a verdict. {note}. Retry on a clean builder "
                f"or escalate to CI. Probe workspaces: {probe_root}",
                flush=True,
            )
            return EXIT_PROBE_INFRA

        if not evaluated:
            # No probe error, but nothing testable (all malformed / refusal /
            # proxy). Route human-review; preserve existing outputs (nothing was
            # tested, so there is no basis to discard a prior reproducer).
            note = _record_preserving()
            print(
                f"no evaluable reproducer in {result.k} draws (all malformed / "
                f"refusal / proxy); routing to human-review. {note}",
                flush=True,
            )
            return EXIT_NO_WINNER

        # Clean, fully-evaluated, none discriminated: a genuine no-winner. The
        # reproducer state changes (any stale reproducer is quarantined), so the
        # canonical sidecar is rewritten to match (winner null, no reproducer).
        quarantined = _quarantine_stale_reproducer(bundle_dir)
        _atomic_write_bytes(canonical_sidecar, sidecar_bytes)
        print(
            f"no discriminating reproducer in {result.k} draws "
            f"({result.discriminating_draws} discriminating); "
            f"routing to human-review. Sidecar: {canonical_sidecar}",
            flush=True,
        )
        if quarantined:
            print(f"quarantined stale reproducer outputs to: {quarantined}", flush=True)
        print(f"probe workspaces kept at: {probe_root}", flush=True)
        return EXIT_NO_WINNER

    _atomic_write_bytes(canonical_sidecar, sidecar_bytes)
    commit_winner(bundle_dir, result)
    print(
        f"winner: draw {result.winner_index} "
        f"(temp {provenance['winner']['temperature']}). Committed reproducer.nix + "
        f"reproducer-log.txt + passthru-tests.json.",
        flush=True,
    )
    print("next: `trace bundle finalize` to refresh manifest hashes, then dispatch "
          "bundle-linux-cert.yml to certify the winner in a clean environment.", flush=True)
    return EXIT_OK


def _validate_finalized_bundle(bundle_dir: Path) -> str | None:
    """Require a finalized, replay-backed bundle before any live model spend.

    Returns an error string or None. bundle.json + replay.json must be present
    and parse, and replay.json must record a Patcher invocation so the
    cross-family rule has something to compare against (otherwise it silently
    passes and a same-family Reproducer could slip through against stale or
    unauditable inputs).
    """
    import hashlib

    from tools.trace_cli.execute import _read_patcher_family_from_replay

    for fname in ("bundle.json", "replay.json"):
        p = bundle_dir / fname
        if not p.is_file():
            return f"bundle is not finalized: {fname} missing (run `trace bundle finalize`)"
        try:
            json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            return f"{fname} is malformed: {exc}"
    if _read_patcher_family_from_replay(bundle_dir) is None:
        return ("replay.json records no Patcher invocation; the cross-family rule "
                "cannot be enforced. Re-finalize the bundle from its executor run.")

    # The Reproducer's inputs must still match the finalized manifest, or a live
    # run bills model calls (and produces signed selection provenance) against
    # inputs that were edited after finalize. Verify each input file the sampler
    # reads against bundle.json.files[...].sha256.
    files_block = json.loads((bundle_dir / "bundle.json").read_text()).get("files") or {}
    placeholder = "d" * 64
    inputs = ["finding.json", "upstream-ref.json", "impact.json", "maintainers.json",
              "package.nix", "patch.diff", "patch-rationale.md"]
    # Bundle-local PoCs under repro/ are model inputs too (surfaced into the
    # prompt), so any that are manifested must also match. (Most bundles do not
    # manifest repro/ artifacts today; verifying manifested ones is
    # forward-compatible and a no-op otherwise.)
    inputs += [k for k in files_block if k.startswith("repro/")]
    for name in inputs:
        entry = files_block.get(name)
        if not entry:
            continue  # not manifested (e.g. minimal bundle); presence is checked later
        expected = entry.get("sha256")
        if not expected or expected == placeholder:
            continue  # placeholder: file was not present at finalize, no hash to check
        p = bundle_dir / name
        if not p.is_file():
            return f"input {name} is in the finalized manifest but missing on disk"
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual != expected:
            return (f"input {name} was edited after finalize "
                    f"(sha {actual[:12]} != manifest {expected[:12]}); re-finalize "
                    "before sampling so provenance matches the inputs")
    return None


def _validate_checkout(checkout: Path, bundle_dir: Path) -> str | None:
    """Precondition-check a nixpkgs checkout for the real local screen.

    Returns an error string or None. The screen resets the checkout to HEAD
    between draws (`git reset --hard` + `clean -fdq`), so a checkout with
    uncommitted work would be silently destroyed; and a checkout whose HEAD is
    not the bundle's pinned nixpkgs_rev builds both arms against the wrong tree,
    producing evidence unrelated to the finalized bundle. Both are refused
    before any model spend.
    """
    import subprocess

    if not checkout.is_dir() or not (checkout / ".git").exists():
        return (f"--nixpkgs-checkout {checkout} is not a git checkout "
                "(patch-apply and per-draw restore need a git working tree)")

    def _git(*a: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(checkout), *a],
                              capture_output=True, text=True)

    status = _git("status", "--porcelain")
    if status.returncode != 0:
        return f"--nixpkgs-checkout {checkout}: git status failed: {status.stderr.strip()}"
    if status.stdout.strip():
        return (f"--nixpkgs-checkout {checkout} has uncommitted changes; the screen "
                "resets it to HEAD between draws and would destroy that work. "
                "Use a clean, disposable checkout.")

    # Pinned-rev check: HEAD must be the bundle's nixpkgs_rev, or the arms build
    # against the wrong tree. Skip only when the bundle records no rev.
    pinned = None
    for fname, key in (("bundle.json", "nixpkgs_rev"), ("finding.json", "nixpkgs_rev")):
        p = bundle_dir / fname
        if p.is_file():
            try:
                pinned = json.loads(p.read_text()).get(key) or pinned
            except json.JSONDecodeError:
                pass
    if pinned:
        head = _git("rev-parse", "HEAD")
        if head.returncode != 0:
            return f"--nixpkgs-checkout {checkout}: git rev-parse HEAD failed"
        head_sha = head.stdout.strip()
        if head_sha != pinned and not head_sha.startswith(pinned) and not pinned.startswith(head_sha):
            return (f"--nixpkgs-checkout HEAD {head_sha[:12]} != bundle nixpkgs_rev "
                    f"{pinned[:12]}; the screen would build against the wrong tree")
    return None


def _write_attempt_record(bundle_dir: Path, sidecar_bytes: bytes) -> Path:
    """Record a failed sweep that PRESERVED the existing reproducer.

    Written to a non-canonical attempts dir (never reproducer-sampling.json), so
    the provenance of the reproducer still on disk is not clobbered by a sweep
    that did not replace it. Unique filename per attempt.
    """
    import tempfile

    root = bundle_dir / ".reproducer-sampling-attempts"
    root.mkdir(exist_ok=True)
    fd, name = tempfile.mkstemp(dir=root, prefix="attempt-", suffix=".json")
    import os

    with os.fdopen(fd, "wb") as fh:
        fh.write(sidecar_bytes)
    return Path(name)


def _quarantine_stale_reproducer(bundle_dir: Path) -> Path | None:
    """Move any pre-existing reproducer outputs aside on a no-winner sweep.

    A failed sweep must not leave a stale reproducer.nix at the canonical path
    where a later finalize/cert would consume it as if this sweep produced it.
    Moving (not deleting) keeps the prior outputs recoverable. Returns the
    quarantine dir if anything was moved, else None.
    """
    import shutil
    import tempfile

    names = ["reproducer.nix", "reproducer-log.txt", "passthru-tests.json"]
    present = [n for n in names if (bundle_dir / n).is_file()]
    if not present:
        return None
    root = bundle_dir / ".reproducer-sampling-quarantine"
    root.mkdir(exist_ok=True)
    # A unique subdir per sweep: a second no-winner --overwrite run must not
    # collide with the first sweep's quarantined files.
    dest = Path(tempfile.mkdtemp(dir=root))
    for n in present:
        shutil.move(str(bundle_dir / n), str(dest / n))
    return dest


def _tool_version() -> str:
    try:
        from tools.trace_cli import __version__  # type: ignore

        return str(__version__)
    except Exception:
        return "unknown"
