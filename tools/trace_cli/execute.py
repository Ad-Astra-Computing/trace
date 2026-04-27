"""Replay execute adapters for v0 deterministic stub roles.

Scope (per docs/DECISIONS.md 2026-04-23 build-order exception + this session):

  deterministic roles supported for --execute:
    * scout
    * cartographer
    * upstream-ref-resolver

  roles rejected for --execute (no model calls in v0):
    * patcher, reviewer, reproducer

  other roles (builder, steward, scout-not-listed-above etc.) are rejected
  with a clear error.

Each executor:
  1. Reads declared input files from the bundle directory.
  2. Verifies each input's sha256 against replay.json unless verify=False.
  3. Calls the appropriate agent stub.
  4. Canonical-JSON serializes the stub's output(s).
  5. Computes output sha256(s), compares to replay.json's recorded values
     unless verify=False. Any mismatch raises HashMismatch.

Canonical JSON = sort_keys=True, separators=",:", ensure_ascii=False. The
same serializer is used everywhere hashes are computed so fixture-writing
(programmatic, in tests) and replay both agree on the bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


DETERMINISTIC_ROLES: frozenset[str] = frozenset({
    "scout",
    "cartographer",
    "upstream-ref-resolver",
})

# Non-deterministic roles need a model call. Patcher is wired; the others
# will follow the same pattern when their prompts + runners land.
MODEL_BACKED_ROLES: frozenset[str] = frozenset({
    "patcher",
})

REJECTED_NON_DETERMINISTIC_ROLES: frozenset[str] = frozenset({
    "reviewer",
    "reproducer",
})


class ExecutionError(Exception):
    """Raised for structural problems (missing input, unsupported role, etc.)."""


class PatcherDispatchRefused(ExecutionError):
    """Patcher must not run on advisory-only / ineligible bundles."""


class HashMismatch(ExecutionError):
    """Raised when an input or output sha256 does not match replay.json."""


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execute(
    role: str,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool = True,
    *,
    model_id: str | None = None,
    adapter_factory: "object | None" = None,
) -> dict[str, Any]:
    """Execute one role invocation for one replay record.

    Deterministic roles run their stub, verify input/output sha256s,
    and return a structural report.

    Patcher runs through its runner (agents.patcher.run_patcher) with
    the supplied model_id + adapter_factory. Hard-fails on advisory-
    only / ineligible-verdict dispatch guards BEFORE the runner is
    invoked. On parser failure, no outputs are written and no replay
    metadata is mutated.

    Returns:
        Deterministic roles:
          {role, invocation_id, outputs[], input_verification[], verified}
        Patcher:
          {role, invocation_id, kind, outputs[], input_verification[], verified,
           patcher_run: {prompt_sha256, user_content_sha256, raw_response_sha256,
                         model_id, sampling, kind, refusal_rule?, refusal_reason?}}
    """
    if role in MODEL_BACKED_ROLES:
        if role != "patcher":
            raise ExecutionError(
                f"role {role!r} is model-backed but not yet wired for --execute"
            )
        if not model_id:
            raise ExecutionError(
                "patcher requires explicit --model <id>; no default live model"
            )
        return _execute_patcher(
            bundle_dir=bundle_dir,
            invocation=invocation,
            verify=verify,
            model_id=model_id,
            adapter_factory=adapter_factory,
        )

    if role in REJECTED_NON_DETERMINISTIC_ROLES:
        raise ExecutionError(
            f"role {role!r} is non-deterministic and not yet wired. Patcher is "
            f"the first to land; Reviewer + Reproducer follow the same pattern."
        )

    if role not in DETERMINISTIC_ROLES:
        raise ExecutionError(
            f"role {role!r} is not supported for --execute in v0 "
            f"(supported: {sorted(DETERMINISTIC_ROLES | MODEL_BACKED_ROLES)})"
        )

    inputs_by_path: dict[str, Any] = {}
    input_verification: list[dict[str, Any]] = []
    for ref in invocation["inputs"]:
        raw, parsed = _load_input(ref, bundle_dir, verify=verify)
        inputs_by_path[ref["path"]] = parsed
        input_verification.append({"path": ref["path"], "verified": verify})

    if role == "scout":
        produced = _execute_scout(inputs_by_path)
    elif role == "cartographer":
        produced = _execute_cartographer(inputs_by_path)
    elif role == "upstream-ref-resolver":
        produced = _execute_upstream_ref_resolver(inputs_by_path)
    else:  # pragma: no cover — guarded above
        raise ExecutionError(f"unreachable role {role!r}")

    outputs = _match_and_hash_outputs(produced, invocation, verify=verify)
    return {
        "role": role,
        "invocation_id": invocation["invocation_id"],
        "outputs": outputs,
        "input_verification": input_verification,
        "verified": verify,
    }


# ─── input loading + hash check ─────────────────────────────────────────────


def _load_input(ref: dict[str, Any], bundle_dir: Path, verify: bool) -> tuple[bytes, Any]:
    path = bundle_dir / ref["path"]
    if not path.is_file():
        raise ExecutionError(f"input file not found: {ref['path']} (looked under {bundle_dir})")
    data = path.read_bytes()
    if verify:
        actual = sha256_hex(data)
        if actual != ref["sha256"]:
            raise HashMismatch(
                f"input hash mismatch for {ref['path']}: "
                f"replay.json declares {ref['sha256']}, file bytes hash to {actual}"
            )
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        parsed = data
    return data, parsed


# ─── role dispatch ──────────────────────────────────────────────────────────


def _execute_scout(inputs: dict[str, Any]) -> list[tuple[str, Any]]:
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    feed = _find_input(inputs, ("feed.json",))
    graph_json = _find_input(inputs, ("graph.json",))
    if feed is None:
        raise ExecutionError("scout: missing 'feed.json' input")
    if graph_json is None:
        raise ExecutionError("scout: missing 'graph.json' input")
    _require_graph_snapshot_shape(graph_json)

    matches = [
        GraphMatch(
            attr_path=m["attr_path"],
            drv_path=m["drv_path"],
            pname=m["pname"],
            version=m["version"],
            cpes=tuple(m.get("cpes", [])),
            purls=tuple(m.get("purls", [])),
            src_url=m.get("src_url"),
            src_hash=m.get("src_hash"),
        )
        for m in graph_json["nodes"]
    ]
    result = scan(feed, CannedGraphLookup(matches))
    if result["status"] == "finding":
        return [("finding.json", result["finding"])]
    return [("mapping-failure.json", result["mapping_failure"])]


def _execute_cartographer(inputs: dict[str, Any]) -> list[tuple[str, Any]]:
    from agents.cartographer import (
        CannedCartographerGraph,
        CannedNode,
        Maintainer,
        analyze,
    )

    finding = _find_input(inputs, ("finding.json",))
    graph_json = _find_input(inputs, ("graph.json",))
    if finding is None:
        raise ExecutionError("cartographer: missing 'finding.json' input")
    if graph_json is not None:
        _require_graph_snapshot_shape(graph_json)
    if graph_json is None:
        raise ExecutionError("cartographer: missing 'graph.json' input")

    nodes = [
        CannedNode(
            attr_path=n["attr_path"],
            drv_path=n["drv_path"],
            pname=n["pname"],
            version=n["version"],
            cpes=tuple(n.get("cpes", [])),
            purls=tuple(n.get("purls", [])),
            reverse_closure=tuple(n.get("reverse_closure", [])),
            critical_downstreams=tuple(n.get("critical_downstreams", [])),
            maintainers=tuple(Maintainer(**m) for m in n.get("maintainers", [])),
        )
        for n in graph_json["nodes"]
    ]
    nixpkgs_rev = graph_json.get("nixpkgs_rev", "0" * 40)
    out = analyze(finding, CannedCartographerGraph(nodes), nixpkgs_rev=nixpkgs_rev)
    return [("impact.json", out["impact"]), ("maintainers.json", out["maintainers"])]


def _execute_upstream_ref_resolver(inputs: dict[str, Any]) -> list[tuple[str, Any]]:
    from agents.upstream_ref_resolver import resolve

    doc = _find_input(inputs, ("resolver-input.json", "input.json"))
    if doc is None:
        raise ExecutionError(
            "upstream-ref-resolver: missing 'resolver-input.json' (or 'input.json') input"
        )
    return [("upstream-ref.json", resolve(doc))]


GRAPH_SNAPSHOT_SCHEMA_VERSION = "1.0.0"


def _require_graph_snapshot_shape(graph_json: Any) -> None:
    """Minimal sanity check; full validation happens via jsonschema in tests.

    At runtime we only verify schema_version so a silent drift (e.g. a
    graph-builder bumped its output format) fails loudly instead of shipping
    wrong bytes into a downstream stub.
    """
    if not isinstance(graph_json, dict):
        raise ExecutionError("graph snapshot must be a JSON object")
    sv = graph_json.get("schema_version")
    if sv != GRAPH_SNAPSHOT_SCHEMA_VERSION:
        raise ExecutionError(
            f"graph snapshot schema_version mismatch: "
            f"expected {GRAPH_SNAPSHOT_SCHEMA_VERSION!r}, got {sv!r}"
        )
    if "nodes" not in graph_json or not isinstance(graph_json["nodes"], list):
        raise ExecutionError("graph snapshot missing required 'nodes' array")


def _find_input(inputs: dict[str, Any], suffixes: tuple[str, ...]) -> Any:
    for suf in suffixes:
        for path, content in inputs.items():
            if path == suf or path.endswith("/" + suf):
                return content
    return None


# ─── output matching + hash comparison ──────────────────────────────────────


def _match_and_hash_outputs(
    produced: list[tuple[str, Any]],
    invocation: dict[str, Any],
    verify: bool,
) -> list[dict[str, Any]]:
    declared = list(invocation["outputs"])
    out: list[dict[str, Any]] = []
    used_indices: set[int] = set()

    for suffix, content in produced:
        idx = None
        for i, ref in enumerate(declared):
            if i in used_indices:
                continue
            if ref["path"] == suffix or ref["path"].endswith("/" + suffix):
                idx = i
                break
        if idx is None:
            raise ExecutionError(
                f"stub produced output {suffix!r} but invocation.outputs does not "
                f"declare a matching path (declared: {[r['path'] for r in declared]})"
            )
        used_indices.add(idx)
        ref = declared[idx]
        body = canonical_json_bytes(content)
        computed = sha256_hex(body)
        if verify and computed != ref["sha256"]:
            raise HashMismatch(
                f"output hash mismatch for {ref['path']}: "
                f"replay.json declares {ref['sha256']}, stub output hashes to {computed}"
            )
        out.append({
            "path": ref["path"],
            "declared_sha256": ref["sha256"],
            "computed_sha256": computed,
            "content": content,
        })

    return out


# ─── patcher (model-backed) ─────────────────────────────────────────────────


PATCHER_PROMPT_PATH_DEFAULT = Path(__file__).resolve().parents[2] / "prompts" / "patcher.v1.md"


def _execute_patcher(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool,
    model_id: str,
    adapter_factory: object | None,
) -> dict[str, Any]:
    """Patcher dispatcher: dispatch-guards, load inputs, run, atomic-write.

    Contract (constraints from the session plan):
      * HARD-FAIL on advisory-only / ineligible bundles before invoking the
        runner. Patcher must never see a cherry-pick-required upstream-ref.
      * Malformed model output stops BEFORE any replay mutation is committed.
        Concretely: run_patcher raises PatcherOutputMalformed; _execute_patcher
        writes no files and records no invocation metadata — the caller sees
        EXIT_INVALID with the diagnosis.
      * Outputs written atomically (temp file + os.replace) so a crash mid-
        write cannot leave a half-written patch.diff or patch-rationale.md.
      * Adapter selection is explicit: if model_id is supplied and no factory
        is provided, AnthropicAdapter is built for claude-* model ids; anything
        else refuses with a clear error. adapter_factory lets tests inject
        FakeAdapter.
    """
    from agents.patcher import (
        AnthropicAdapter,
        PatcherOutputMalformed,
        run_patcher,
    )

    # Dispatch guards. These check the bundle itself, not the invocation
    # record — the bundle is the authoritative state on whether Patcher
    # should even be invoked.
    bundle_path = bundle_dir / "bundle.json"
    if bundle_path.is_file():
        try:
            bundle = json.loads(bundle_path.read_text())
        except Exception as exc:
            raise ExecutionError(f"failed to read bundle.json: {exc}") from exc
        kind = bundle.get("kind")
        if kind == "advisory-only":
            raise PatcherDispatchRefused(
                "refuses: bundle.kind=='advisory-only'. Patcher must not "
                "be invoked on advisory-only bundles per prompts/patcher.v1.md "
                "refusal rules + SPEC §1.2 separation of concerns."
            )

    upstream_ref_path = bundle_dir / "upstream-ref.json"
    if not upstream_ref_path.is_file():
        raise ExecutionError("patcher requires upstream-ref.json in bundle_dir")
    upstream_ref = json.loads(upstream_ref_path.read_text())
    verdict = (upstream_ref.get("eligibility") or {}).get("verdict")
    if not isinstance(verdict, str):
        raise ExecutionError(
            "patcher refuses: upstream-ref.json has no eligibility.verdict"
        )
    if verdict.startswith("ineligible-"):
        raise PatcherDispatchRefused(
            f"refuses: upstream-ref.eligibility.verdict=={verdict!r}. "
            f"Ineligible bundles go to the advisory-only path without "
            f"invoking Patcher."
        )
    if verdict not in ("eligible", "eligible-requires-human-review"):
        raise ExecutionError(
            f"patcher refuses: upstream-ref.eligibility.verdict=={verdict!r} "
            f"is not a dispatchable verdict"
        )

    # Load the other standard inputs.
    finding_path = bundle_dir / "finding.json"
    impact_path = bundle_dir / "impact.json"
    maintainers_path = bundle_dir / "maintainers.json"
    package_path = bundle_dir / "package.nix"
    for p in (finding_path, impact_path, maintainers_path, package_path):
        if not p.is_file():
            raise ExecutionError(
                f"patcher requires {p.name} in bundle_dir (missing: {p})"
            )
    finding = json.loads(finding_path.read_text())
    impact = json.loads(impact_path.read_text())
    maintainers = json.loads(maintainers_path.read_text())
    package_source = package_path.read_text()

    input_verification: list[dict[str, Any]] = []
    if verify and invocation.get("inputs"):
        # When a replay-recorded invocation exists, verify declared inputs
        # against disk. Fresh runs bypass this (no recorded inputs yet).
        for ref in invocation["inputs"]:
            try:
                _raw, _parsed = _load_input(ref, bundle_dir, verify=True)
            except HashMismatch:
                raise
            except ExecutionError:
                # Missing-file here is an input-not-present diagnostic,
                # which is already raised above for the four required files.
                raise
            input_verification.append({"path": ref["path"], "verified": True})
    else:
        input_verification = [
            {"path": p.name, "verified": False}
            for p in (finding_path, upstream_ref_path, impact_path, maintainers_path, package_path)
        ]

    # Build adapter.
    if adapter_factory is not None:
        adapter = adapter_factory(model_id)  # type: ignore[misc]
    elif model_id.startswith("claude-"):
        adapter = AnthropicAdapter(model_id)
    else:
        raise ExecutionError(
            f"no adapter wired for model id {model_id!r}. Supply an adapter_factory "
            f"or pass a claude-* model id (AnthropicAdapter is the only wired path)."
        )

    inputs = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_source,
        "package_source_path": str(package_path.name),
    }

    # Parse-before-write: if run_patcher raises PatcherOutputMalformed, we
    # exit without touching any files. The caller sees EXIT_INVALID.
    started_at = _utc_now_iso()
    try:
        result = run_patcher(
            inputs=inputs,
            adapter=adapter,
            prompt_path=PATCHER_PROMPT_PATH_DEFAULT,
        )
    except PatcherOutputMalformed as exc:
        raise ExecutionError(f"patcher output malformed: {exc}") from exc
    ended_at = _utc_now_iso()

    # Atomic writes. Temp file + os.replace guarantees no half-written artifact.
    outputs: list[dict[str, Any]] = []
    if result.kind == "patch":
        diff_bytes = (result.parsed.patch_diff or "").encode("utf-8")
        rat_bytes = (result.parsed.patch_rationale_md or "").encode("utf-8")
        # Defensive trailing-newline guarantee. The model frequently
        # ends its diff body without a final newline (the parser's
        # lazy-match captures everything up to the END marker; the END
        # marker eats the model's pre-marker `\n`). Without a trailing
        # newline `git apply --check` reports "corrupt patch" and the
        # patch fails to apply via strict tools even though the
        # permissive `patch` tool fuzzy-applies it. Surfaced by
        # openssl_3 run on 2026-04-27.
        if diff_bytes and not diff_bytes.endswith(b"\n"):
            diff_bytes += b"\n"
        if rat_bytes and not rat_bytes.endswith(b"\n"):
            rat_bytes += b"\n"
        _atomic_write_bytes(bundle_dir / "patch.diff", diff_bytes)
        _atomic_write_bytes(bundle_dir / "patch-rationale.md", rat_bytes)
        outputs = [
            {"path": "patch.diff", "sha256": sha256_hex(diff_bytes), "bytes": len(diff_bytes)},
            {"path": "patch-rationale.md", "sha256": sha256_hex(rat_bytes), "bytes": len(rat_bytes)},
        ]
    else:  # refusal
        refusal_body = json.dumps(
            {
                "rule": result.parsed.refusal_rule,
                "reason": result.parsed.refusal_reason,
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        _atomic_write_bytes(bundle_dir / "refusal.json", refusal_body)
        outputs = [
            {"path": "refusal.json", "sha256": sha256_hex(refusal_body), "bytes": len(refusal_body)},
        ]

    patcher_run_meta: dict[str, Any] = {
        "prompt_sha256": result.prompt_sha256,
        "user_content_sha256": result.user_content_sha256,
        "raw_response_sha256": result.raw_response_sha256,
        "model_id": result.model_response.model_id,
        "sampling": result.sampling,
        "kind": result.kind,
        "refusal_rule": result.parsed.refusal_rule,
        "refusal_reason": result.parsed.refusal_reason,
        "adapter": result.model_response.extras.get("adapter"),
    }

    # Append a canonical replay-shape invocation entry into replay.json. Done
    # AFTER atomic writes so a partial / malformed parse doesn't pollute
    # replay history. Only the role/invocation entry is appended; top-level
    # replay.json fields are left intact.
    replay_invocation = _build_patcher_invocation(
        bundle_dir=bundle_dir,
        patcher_run=patcher_run_meta,
        outputs=outputs,
        started_at=started_at,
        ended_at=ended_at,
    )
    _append_patcher_replay_entry(
        bundle_dir=bundle_dir, invocation=replay_invocation
    )

    return {
        "role": "patcher",
        "invocation_id": replay_invocation["invocation_id"],
        "kind": result.kind,
        "outputs": outputs,
        "input_verification": input_verification,
        "verified": verify,
        "patcher_run": patcher_run_meta,
        "replay_invocation": replay_invocation,
    }


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write bytes atomically to target via temp file + os.replace."""
    import os
    import tempfile

    target_parent = target.parent
    target_parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target_parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        raise


# ─── replay metadata writer (patcher) ──────────────────────────────────────


def _build_patcher_model_block(patcher_run: dict[str, Any]) -> dict[str, Any]:
    """Build the model{} field for a Patcher invocation in replay.json.

    Family/vendor are derived from the model_id and the adapter that ran;
    `fake` adapters map to the deterministic-no-model family so unit tests
    stay schema-valid.
    """
    model_id = patcher_run["model_id"]
    adapter_kind = patcher_run.get("adapter") or "unknown"
    if adapter_kind == "fake":
        family, vendor, version = "deterministic-no-model", "internal", "fake"
    elif model_id.startswith("claude-"):
        family, vendor = "anthropic", "anthropic"
        version = model_id[len("claude-"):] or "unknown"
    else:
        family, vendor, version = "open-weights-other", "unknown", "unknown"

    sampling_in = patcher_run.get("sampling") or {}
    sampling_out: dict[str, Any] = {
        "temperature": float(sampling_in.get("temperature", 0.0)),
        "top_p": float(sampling_in.get("top_p", 1.0)),
        "max_tokens": int(sampling_in.get("max_tokens", 8192)),
    }
    if "seed" in sampling_in and sampling_in["seed"] is not None:
        sampling_out["seed"] = int(sampling_in["seed"])

    return {
        "family": family,
        "vendor": vendor,
        "model_id": model_id,
        "version": version,
        "sampling": sampling_out,
    }


def _utc_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gen_invocation_id() -> str:
    import uuid
    return str(uuid.uuid4())


def _file_sha256(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def _build_patcher_invocation(
    *,
    bundle_dir: Path,
    patcher_run: dict[str, Any],
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
) -> dict[str, Any]:
    """Build a single replay-shape invocation record for a Patcher run."""
    inputs = []
    for fname in ("finding.json", "upstream-ref.json", "impact.json", "maintainers.json", "package.nix"):
        p = bundle_dir / fname
        if p.is_file():
            inputs.append({"path": fname, "sha256": _file_sha256(p)})

    invocation = {
        "invocation_id": _gen_invocation_id(),
        "role": "patcher",
        "started_at": started_at,
        "ended_at": ended_at,
        "model": _build_patcher_model_block(patcher_run),
        "prompt": {"path": "prompts/patcher.v1.md", "sha256": patcher_run["prompt_sha256"]},
        "inputs": inputs,
        "outputs": [{"path": o["path"], "sha256": o["sha256"]} for o in outputs],
        "rng_seed": None,
        "validators_passed": _patcher_validators_for(patcher_run),
        "network_policy_applied": "none",
    }
    return invocation


def _patcher_validators_for(patcher_run: dict[str, Any]) -> list[str]:
    """Names of declared validators that the Patcher output passed.

    Parser-level success implies schema-valid-output. Refusal implies a
    valid refusal block. These are the structural validators only; the
    five Patcher scorers (next milestone) compute richer signals against
    these recorded outputs.
    """
    if patcher_run.get("kind") == "refusal":
        return ["refusal-shape"]
    return ["schema-valid-output"]


def _append_patcher_replay_entry(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
) -> None:
    """Append a Patcher invocation into replay.json's roles[]."""
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        raise ExecutionError(
            f"replay.json missing in {bundle_dir}; replay-metadata writer requires "
            f"a pre-existing replay.json with the standard top-level fields. "
            f"Fresh-on-empty creation is out of scope here."
        )
    replay = json.loads(replay_path.read_text())

    roles = replay.setdefault("roles", [])
    role_entry = None
    for r in roles:
        if r.get("role") == "patcher":
            role_entry = r
            break
    if role_entry is None:
        role_entry = {"role": "patcher", "invocations": []}
        roles.append(role_entry)
    role_entry["invocations"].append(invocation)

    body = json.dumps(replay, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_bytes(replay_path, body.encode("utf-8"))
