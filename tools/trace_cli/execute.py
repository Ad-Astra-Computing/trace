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

# Non-deterministic roles need a model call. Patcher, Reviewer, and
# Reproducer are wired (the latter as of the 2026-04-28 step-4 lock).
MODEL_BACKED_ROLES: frozenset[str] = frozenset({
    "patcher",
    "reviewer",
    "reproducer",
})

# Builder is deterministic (no LLM call) but its execution shape is
# subprocess-driven (shells out to nix-build via the BuildRunner
# Protocol), distinct from the in-process deterministic roles. Live
# Builder execution requires a Linux build host; the wiring lands
# regardless so the FakeBuildRunner-driven tests can exercise the
# integration.
RUNNER_BACKED_ROLES: frozenset[str] = frozenset({
    "builder",
})

REJECTED_NON_DETERMINISTIC_ROLES: frozenset[str] = frozenset()


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
    build_runner_factory: "object | None" = None,
    nixpkgs_checkout: Path | None = None,
    builder_timeout_seconds: int | None = None,
    reviewer_prompt_path: Path | None = None,
    max_tokens: int | None = None,
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
        if not model_id:
            raise ExecutionError(
                f"{role} requires explicit --model <id>; no default live model"
            )
        if max_tokens is not None and max_tokens < 1:
            raise ExecutionError("--max-tokens must be a positive integer")
        if role == "patcher":
            return _execute_patcher(
                bundle_dir=bundle_dir,
                invocation=invocation,
                verify=verify,
                model_id=model_id,
                adapter_factory=adapter_factory,
                max_tokens=max_tokens,
            )
        if role == "reviewer":
            return _execute_reviewer(
                bundle_dir=bundle_dir,
                invocation=invocation,
                verify=verify,
                model_id=model_id,
                adapter_factory=adapter_factory,
                prompt_path=reviewer_prompt_path,
                max_tokens=max_tokens,
            )
        if role == "reproducer":
            return _execute_reproducer(
                bundle_dir=bundle_dir,
                invocation=invocation,
                verify=verify,
                model_id=model_id,
                adapter_factory=adapter_factory,
            )
        raise ExecutionError(
            f"role {role!r} is model-backed but not yet wired for --execute"
        )

    if role in RUNNER_BACKED_ROLES:
        return _execute_builder(
            bundle_dir=bundle_dir,
            invocation=invocation,
            verify=verify,
            build_runner_factory=build_runner_factory,
            nixpkgs_checkout=nixpkgs_checkout,
            builder_timeout_seconds=builder_timeout_seconds,
        )

    if role in REJECTED_NON_DETERMINISTIC_ROLES:
        raise ExecutionError(
            f"role {role!r} is non-deterministic and not yet wired. Patcher "
            f"and Reviewer have landed; Reproducer follows the same pattern."
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


PATCHER_PROMPT_PATH_DEFAULT = Path(__file__).resolve().parents[2] / "prompts" / "patcher.v2.2.md"
# Used only when upstream-ref.json.eligibility.patch_strategy == "source-backport":
# the v3 prompt authorizes the Patcher to author an in-tree backport patch
# against the current version instead of bumping to the fixed release.
PATCHER_PROMPT_PATH_BACKPORT = Path(__file__).resolve().parents[2] / "prompts" / "patcher.v3.md"
# Used when a source-backport bundle carries a source-context/ dir (schema 1.1.0):
# the v4 prompt gives the Patcher the pre-patch source of the affected files plus
# the deterministic preflight verdict (applies_verbatim), so it transcribes
# verbatim when the upstream fix applies and authors a grounded semantic
# adaptation when the pinned base has diverged (semantic-backport-adaptation arc).
PATCHER_PROMPT_PATH_ADAPT = Path(__file__).resolve().parents[2] / "prompts" / "patcher.v4.md"


def _persist_role_failure(
    *,
    role: str,  # "patcher" | "reviewer" | "reproducer"
    bundle_dir: Path,
    exc: Any,  # *OutputMalformed exception with optional raw_response attrs
    model_id: str,
    started_at: str,
    prompt_path_relative: str,
) -> None:
    """Persist a failed model invocation's context for debugging.

    Writes `.{role}-failures/<uuid>/raw-response.txt` (the model's actual
    output) and `failure.json` (model_id, prompt sha, raw response sha,
    parser error, timestamp). The directory is NOT part of the replay
    manifest and is gitignored at the repo level. If the exception lacks
    raw_response context (e.g., raised before run_<role> reached the
    parser), this helper writes only the metadata it can resolve.
    (Added 2026-05-25 with patcher.v2 / F19; extended to reproducer
    2026-05-25 after the libxmp reproducer hit the same gap.)
    """
    import uuid

    raw = getattr(exc, "raw_response", None)
    raw_sha = getattr(exc, "raw_response_sha256", None)
    prompt_sha = getattr(exc, "prompt_sha256", None)
    user_content_sha = getattr(exc, "user_content_sha256", None)

    failure_id = str(uuid.uuid4())
    fail_dir = bundle_dir / f".{role}-failures" / failure_id
    try:
        fail_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        # Vanishingly improbable UUID collision; bail out rather than
        # overwrite. The next live attempt will mint a fresh UUID.
        return

    if raw is not None:
        _atomic_write_bytes(fail_dir / "raw-response.txt", raw.encode("utf-8"))

    failure_meta = {
        "schema_version": "1.1.0",
        "role": role,
        "failure_id": failure_id,
        "started_at": started_at,
        "failed_at": _utc_now_iso(),
        "model_id": getattr(exc, "model_id", None) or model_id,
        "prompt_sha256": prompt_sha,
        "prompt_path": prompt_path_relative,
        "user_content_sha256": user_content_sha,
        "raw_response_sha256": raw_sha,
        "parser_error": str(exc),
        "raw_response_bytes": (len(raw.encode("utf-8")) if raw else 0),
    }
    # Record the failed attempt's realized spend when the exception carries its
    # model response. A retried review bills earlier attempts into the success
    # sidecar; but on TERMINAL exhaustion no sidecar is written, so without this
    # the spent tokens would vanish from every artifact. This keeps a per-attempt
    # forensic record (the failures dir is gitignored / not in replay) so cost
    # can always be reconstructed. None when the failure preceded the model call.
    model_response = getattr(exc, "model_response", None)
    if model_response is not None:
        from agents.cost import actual_cost_usd

        in_tok = getattr(model_response, "input_tokens", None)
        out_tok = getattr(model_response, "output_tokens", None)
        cache_creation = getattr(model_response, "cache_creation_input_tokens", None)
        cache_read = getattr(model_response, "cache_read_input_tokens", None)
        failure_meta["usage"] = {
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "cache_creation_input_tokens": cache_creation,
            "cache_read_input_tokens": cache_read,
        }
        failure_meta["actual_cost_usd"] = actual_cost_usd(
            model_id=getattr(exc, "model_id", None) or model_id,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cache_creation_input_tokens=cache_creation,
            cache_read_input_tokens=cache_read,
        )
    failure_body = (json.dumps(failure_meta, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write_bytes(fail_dir / "failure.json", failure_body)


def _execute_patcher(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool,
    model_id: str,
    adapter_factory: object | None,
    max_tokens: int | None = None,
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
    from tools.trace_cli.hunk_normalizer import (
        HunkNormalizationError,
        canonicalize_backport_patch,
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
                "be invoked on advisory-only bundles per prompts/patcher.v2.2.md "
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
    else:
        adapter = _build_adapter_from_model_id(model_id, role_label="patcher")

    inputs = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_source,
        "package_source_path": str(package_path.name),
    }

    # Source-backport strategy (resolver-authorized; the Patcher cannot choose
    # it). When upstream-ref.json.eligibility.patch_strategy == "source-backport"
    # the Patcher AUTHORS the upstream fix as an in-tree patch against the
    # CURRENT version instead of bumping to the fixed release. It is fed the
    # supplied `upstream-fix.patch` (the upstream commit diff with provenance;
    # no network) as ground truth for the fix content, and runs under the v3
    # prompt that authorizes the backport-patch shape.
    patch_strategy = (upstream_ref.get("eligibility") or {}).get("patch_strategy")
    patcher_prompt_path = PATCHER_PROMPT_PATH_DEFAULT
    if patch_strategy == "source-backport":
        fix_patch_path = bundle_dir / "upstream-fix.patch"
        if not fix_patch_path.is_file():
            raise ExecutionError(
                "patcher source-backport requires upstream-fix.patch in bundle_dir "
                "(the resolver-supplied upstream commit diff)"
            )
        # Replay integrity: in --verify mode the recorded invocation MUST declare
        # upstream-fix.patch as an input (the patch the Patcher transcribes), or
        # replay could silently use a different, un-hashed ground truth.
        if verify and invocation.get("inputs") and not any(
            ref.get("path") == "upstream-fix.patch" for ref in invocation["inputs"]
        ):
            raise ExecutionError(
                "patcher source-backport replay verification: upstream-fix.patch is "
                "not declared in the recorded invocation inputs; refusing to read it "
                "unverified (re-run without --verify to regenerate the invocation)"
            )
        inputs["upstream_fix_patch"] = fix_patch_path.read_text()
        inputs["patch_strategy"] = "source-backport"
        patcher_prompt_path = PATCHER_PROMPT_PATH_BACKPORT
        if not any(ref.get("path") == "upstream-fix.patch" for ref in input_verification):
            input_verification.append({"path": "upstream-fix.patch", "verified": False})

        # Semantic-adaptation lane (patcher.v4): a source-context/ dir means this
        # bundle carries the pre-patch source of the affected files (a schema-1.1.0
        # signed input). Feed it, plus the deterministic preflight verdict baked at
        # bootstrap (preflight.json.applies_verbatim), so v4 transcribes verbatim
        # when the fix applies and authors a grounded adaptation when it does not.
        source_context_dir = bundle_dir / "source-context"
        sc_relpaths = (
            _source_context_relpaths(source_context_dir)
            if source_context_dir.is_dir() else []
        )
        # Only the adaptation lane when source-context actually carries files. An
        # empty dir must NOT route to v4 (it would run v4 with no context while
        # finalize emits a 1.0.0 bundle — an inconsistent, unsigned v4 contract).
        if sc_relpaths:
            inputs["source_context"] = {
                rel: (source_context_dir / rel).read_text()
                for rel in sc_relpaths
            }
            preflight_path = bundle_dir / "preflight.json"
            if preflight_path.is_file():
                pf = json.loads(preflight_path.read_text())
                inputs["applies_verbatim"] = pf.get("applies_verbatim")
                inputs["preflight_diagnostics"] = pf.get("diagnostics", "")
            else:
                # No baked verdict: fail closed to adaptation (the model must
                # ground its change in source-context rather than assume verbatim).
                inputs["applies_verbatim"] = None
                inputs["preflight_diagnostics"] = ""
            patcher_prompt_path = PATCHER_PROMPT_PATH_ADAPT

            # Replay integrity: a recorded v4 invocation MUST declare the
            # source-context files (and preflight.json when present) as inputs, or
            # replay could run the adaptation lane against different/absent source.
            if verify and invocation.get("inputs"):
                declared = {ref.get("path") for ref in invocation["inputs"]}
                need = {f"source-context/{rel}" for rel in sc_relpaths}
                if preflight_path.is_file():
                    need.add("preflight.json")
                missing = sorted(need - declared)
                if missing:
                    raise ExecutionError(
                        "patcher source-context replay verification: "
                        f"{missing} not declared in the recorded invocation inputs; "
                        "refusing to read them unverified (re-run without --verify)"
                    )
            # Only record inputs not already covered: in --verify mode the generic
            # loop above has already appended these with verified:True, and a
            # duplicate verified:False entry would contradict it.
            _already = {v.get("path") for v in input_verification}
            for rel in sc_relpaths:
                key = f"source-context/{rel}"
                if key not in _already:
                    input_verification.append({"path": key, "verified": False})
            if preflight_path.is_file() and "preflight.json" not in _already:
                input_verification.append({"path": "preflight.json", "verified": False})

    # Parse-before-write: if run_patcher raises PatcherOutputMalformed, we
    # exit without touching any bundle artifacts (no patch.diff, no
    # replay invocation). To preserve debugging context — the model already
    # billed for the call — we persist `.patcher-failures/<uuid>/raw-
    # response.txt` + `failure.json` outside the signed bundle surface.
    # The directory is not part of the replay manifest and is gitignored at
    # the repo level. (Added 2026-05-25 with patcher.v2 / F19.)
    started_at = _utc_now_iso()
    try:
        result = run_patcher(
            inputs=inputs,
            adapter=adapter,
            prompt_path=patcher_prompt_path,
            sampling=({"max_tokens": max_tokens} if max_tokens is not None else None),
        )
    except PatcherOutputMalformed as exc:
        _persist_role_failure(
            role="patcher",
            bundle_dir=bundle_dir,
            exc=exc,
            model_id=model_id,
            started_at=started_at,
            prompt_path_relative=f"prompts/{patcher_prompt_path.name}",
        )
        raise ExecutionError(f"patcher output malformed: {exc}") from exc
    ended_at = _utc_now_iso()

    # Atomic writes. Temp file + os.replace guarantees no half-written artifact.
    outputs: list[dict[str, Any]] = []
    hunk_normalization: dict[str, Any] | None = None
    if result.kind == "patch":
        diff_text = result.parsed.patch_diff or ""

        # Adaptation-lane canonical compilation (DECISIONS 2026-07-27). The
        # verbatim lane copies the upstream patch as-is; only the adaptation lane
        # AUTHORS a patch, and the model reliably emits a NON-CANONICAL artifact:
        # miscomputed / bare `@@` headers (libarchive `@@ -3517,13` for a body at
        # 3443; maxima literal `@@` with no ranges) AND non-canonical bodies
        # (redundant delete+re-add of byte-identical lines, missing trailing
        # context) that GNU `patch`/`git apply` reject at default fuzz even when
        # every line matches the pinned source. This is a TRANSPARENT COMPILATION
        # step, not a correction of model intent: the postimage is reconstructed
        # solely from the model's own old/new body (each hunk matched exactly and
        # uniquely against source-context), then re-diffed against the pinned
        # source. It changes representation, never meaning — semantic mistakes stay
        # in the postimage and remain visible to Reviewer/Builder. The compiler
        # verifies the canonical diff re-applies at fuzz 0 and reproduces the
        # postimage (its internal invariant); it fails loud (does not silently
        # "fix") on an ungroundable / ambiguous / overlapping body. Runs only on the
        # adaptation lane (source-context present, applies_verbatim not True).
        source_context = inputs.get("source_context")
        if source_context and inputs.get("applies_verbatim") is not True:
            pre_sha = sha256_hex(diff_text.encode("utf-8"))
            try:
                canon = canonicalize_backport_patch(diff_text, source_context)
            except HunkNormalizationError as exc:
                # Fail-don't-fix: the authored body is not grounded in the pinned
                # source (ambiguous / absent / overlapping), so no honest canonical
                # patch can be compiled. Persist the raw patch for debugging (the
                # model call already billed) and abort before writing/signing.
                setattr(exc, "raw_response", diff_text)
                setattr(exc, "raw_response_sha256", pre_sha)
                _persist_role_failure(
                    role="patcher",
                    bundle_dir=bundle_dir,
                    exc=exc,
                    model_id=model_id,
                    started_at=started_at,
                    prompt_path_relative=f"prompts/{patcher_prompt_path.name}",
                )
                raise ExecutionError(
                    f"patcher hunk-header canonicalization failed: {exc}"
                ) from exc
            diff_text = canon.text
            hunk_normalization = {
                "applied": canon.changed,
                "pre_sha256": pre_sha,
                "files": canon.files,
            }

        diff_bytes = diff_text.encode("utf-8")
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
        if hunk_normalization is not None:
            hunk_normalization["post_sha256"] = sha256_hex(diff_bytes)
        _atomic_write_bytes(bundle_dir / "patch.diff", diff_bytes)
        _atomic_write_bytes(bundle_dir / "patch-rationale.md", rat_bytes)
        outputs = [
            {"path": "patch.diff", "sha256": sha256_hex(diff_bytes), "bytes": len(diff_bytes)},
            {"path": "patch-rationale.md", "sha256": sha256_hex(rat_bytes), "bytes": len(rat_bytes)},
        ]
        # Adaptation lane: emit a signed applicability attestation the Reviewer
        # treats as deterministic evidence that the canonical patch.diff is the
        # artifact Builder will execute. Reaching this point means the canonical
        # compiler already PROVED (fail-closed) that every hunk matched the pinned
        # source uniquely and the canonical diff re-applies at fuzz 0 reproducing the
        # recorded postimage — so those verdicts are `true` by construction here.
        if hunk_normalization is not None:
            from tools.trace_cli.hunk_normalizer import CANONICALIZER_VERSION

            attestation = {
                "schema_version": "1.0.0",
                "canonicalizer_version": CANONICALIZER_VERSION,
                "raw_patch_sha256": hunk_normalization["pre_sha256"],
                "canonical_patch_sha256": hunk_normalization["post_sha256"],
                "canonicalized": hunk_normalization["applied"],
                "unique_source_match": True,
                "applies_at_fuzz0": True,
                "files": hunk_normalization["files"],
            }
            att_bytes = (
                json.dumps(attestation, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            )
            _atomic_write_bytes(bundle_dir / "patch-applicability.json", att_bytes)
            outputs.append(
                {
                    "path": "patch-applicability.json",
                    "sha256": sha256_hex(att_bytes),
                    "bytes": len(att_bytes),
                }
            )
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
    if hunk_normalization is not None:
        patcher_run_meta["hunk_normalization"] = hunk_normalization

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
        prompt_path_relative=f"prompts/{patcher_prompt_path.name}",
    )

    # Write the cost sidecar BEFORE the replay-append. The model spend
    # has already happened; if replay-append then fails (e.g. missing
    # replay.json on a fresh-bundle path) we still want the cost data
    # captured so the auditor can reconcile the spend.
    _write_role_invocation_sidecar(
        bundle_dir=bundle_dir,
        role="patcher",
        cve_id=_read_bundle_cve_id(bundle_dir),
        invocation_id=replay_invocation["invocation_id"],
        started_at=started_at,
        ended_at=ended_at,
        role_run_meta=patcher_run_meta,
        model_response=result.model_response,
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


def _read_bundle_cve_id(bundle_dir: Path) -> str | None:
    """Best-effort read of bundle.json#cve_id for sidecar provenance.
    Returns None rather than raising if bundle.json is missing or
    malformed: the sidecar is still valuable without the cve_id, and
    we don't want a missing-bundle.json to break the role write."""
    bundle_path = bundle_dir / "bundle.json"
    if not bundle_path.is_file():
        return None
    try:
        return json.loads(bundle_path.read_text()).get("cve_id")
    except (json.JSONDecodeError, OSError):
        return None


def _write_role_invocation_sidecar(
    *,
    bundle_dir: Path,
    role: str,
    cve_id: str | None,
    invocation_id: str,
    started_at: str,
    ended_at: str,
    role_run_meta: dict[str, Any],
    model_response: Any,
    extra_usages: list[Any] | None = None,
) -> Path:
    """Write a <role>-invocation.json sidecar capturing usage + cost.

    Mirrors agents/patcher/cli.py's patcher-invocation.json shape so
    `trace report throughput` can read all three roles uniformly. The
    sidecar is the single source of truth for realized per-role spend;
    replay.json carries the invocation in roles[] but is bound by its
    schema (additionalProperties: false) and can't carry usage data.

    `extra_usages` (Reviewer retry path) are additional model responses —
    earlier malformed attempts that still spent tokens. The headline `usage`
    block and `actual_cost_usd` SUM over `[model_response, *extra_usages]` so
    a retried review bills its full realized spend, not only the conforming
    attempt. model_id / adapter / shas stay from the successful `model_response`.

    Returns the path written. Caller is expected to log the path or
    surface it in the test/CI artifact list.
    """
    from agents.cost import actual_cost_usd

    model_id = model_response.model_id
    # Sum a usage field across every attempt, None-safe. A total is only
    # honest if EVERY attempt reported the field: if ANY attempt's field is
    # None (FakeAdapter/OpenAI unobserved case, or a partial-observability
    # mix) keep the total None so cost stays 'unobserved' rather than a
    # spurious partial sum that reads as a complete total.
    all_responses = [model_response, *(extra_usages or [])]

    def _sum_field(name: str) -> int | None:
        vals = [getattr(r, name, None) for r in all_responses]
        if any(v is None for v in vals):
            return None
        return sum(vals)

    input_tokens = _sum_field("input_tokens")
    output_tokens = _sum_field("output_tokens")
    cache_creation = _sum_field("cache_creation_input_tokens")
    cache_read = _sum_field("cache_read_input_tokens")
    cost = actual_cost_usd(
        model_id=model_id,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_creation_input_tokens=cache_creation,
        cache_read_input_tokens=cache_read,
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "invocation_id": invocation_id,
        "cve_id": cve_id,
        "role": role,
        "started_at": started_at,
        "ended_at": ended_at,
        "model_id": model_id,
        "adapter": role_run_meta.get("adapter"),
        "kind": role_run_meta.get("kind"),
        "sampling": role_run_meta.get("sampling"),
        "prompt_sha256": role_run_meta.get("prompt_sha256"),
        "user_content_sha256": role_run_meta.get("user_content_sha256"),
        "raw_response_sha256": role_run_meta.get("raw_response_sha256"),
        "usage": {
            # input_tokens is the *uncached* new-input count; the two
            # cache fields complete the picture for prompt-cached
            # adapters (Anthropic). Non-caching adapters leave both
            # cache fields at None. All four are SUMMED across attempts
            # on the Reviewer retry path (see extra_usages).
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens": cache_creation,
            "cache_read_input_tokens": cache_read,
            # Number of model calls this spend covers (1 + retried attempts).
            # Always >= 1; only meaningful for the Reviewer retry path.
            "attempts": len(all_responses),
        },
        "budget": {
            # Reviewer + Reproducer have no CLI-set budget caps in v0;
            # actual_cost_usd is the realized spend, null when the
            # adapter didn't report token usage (FakeAdapter case).
            "soft_cap_usd": None,
            "hard_cap_usd": None,
            "actual_cost_usd": cost,
        },
    }
    # v2 attestation validator field: propagate from reviewer_run_meta if present.
    # For non-reviewer roles this key will be absent from role_run_meta and is
    # not written (keeps sidecar shape clean for Patcher/Reproducer).
    if "attestation_grounded" in role_run_meta:
        payload["attestation_grounded"] = role_run_meta["attestation_grounded"]
    # Bounded auto-retry metrics (Reviewer only; REVIEWER_MAX_ATTEMPTS). Absent
    # from role_run_meta for Patcher/Reproducer, so the sidecar shape for those
    # roles is unchanged.
    if "first_attempt_conformant" in role_run_meta:
        payload["first_attempt_conformant"] = role_run_meta["first_attempt_conformant"]
    if "retry_count" in role_run_meta:
        payload["retry_count"] = role_run_meta["retry_count"]
    if "reviewer_attempts" in role_run_meta:
        payload["reviewer_attempts"] = role_run_meta["reviewer_attempts"]
    # Adaptation-lane hunk-header normalization provenance (Patcher only). Records
    # the pre/post patch sha256 and every header rewrite so an auditor can see
    # exactly what the deterministic normalizer changed before the patch was signed.
    if "hunk_normalization" in role_run_meta:
        payload["hunk_normalization"] = role_run_meta["hunk_normalization"]
    sidecar_path = bundle_dir / f"{role}-invocation.json"
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write_bytes(sidecar_path, body)
    return sidecar_path


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


def _source_context_relpaths(source_context_dir: Path) -> list[str]:
    """Sorted POSIX relative paths of regular files under source-context/.

    Symlinks are refused (a signed replay input must be real bytes, never a
    pointer out of the bundle) — matching the finalize-time guard in bundle.py.
    """
    # Reject a symlinked root before rglob() follows it out of the bundle.
    if source_context_dir.is_symlink():
        raise ExecutionError(
            f"source-context root is a symlink ({source_context_dir}); refusing "
            "to read replay inputs through it."
        )
    rels: list[str] = []
    for p in source_context_dir.rglob("*"):
        if p.is_symlink():
            raise ExecutionError(
                f"source-context contains a symlink ({p}); only regular files "
                "are allowed as signed replay inputs."
            )
        if p.is_file():
            rels.append(p.relative_to(source_context_dir).as_posix())
    return sorted(rels)


def _build_patcher_invocation(
    *,
    bundle_dir: Path,
    patcher_run: dict[str, Any],
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
    prompt_path_relative: str = "prompts/patcher.v2.2.md",
) -> dict[str, Any]:
    """Build a single replay-shape invocation record for a Patcher run."""
    inputs = []
    # upstream-fix.patch is replay-critical input ONLY on the source-backport
    # path (resolver-supplied upstream commit diff the Patcher transcribes).
    input_files = ["finding.json", "upstream-ref.json", "impact.json", "maintainers.json", "package.nix"]
    if (bundle_dir / "upstream-fix.patch").is_file():
        input_files.append("upstream-fix.patch")
    # source-context inputs (patcher.v4 semantic-adaptation lane): the pre-patch
    # source of the affected files + the deterministic preflight verdict. Recorded
    # as replay-critical patcher inputs so a replay re-runs v4 on the same bytes.
    source_context_dir = bundle_dir / "source-context"
    if source_context_dir.is_dir():
        input_files += [
            f"source-context/{rel}" for rel in _source_context_relpaths(source_context_dir)
        ]
        if (bundle_dir / "preflight.json").is_file():
            input_files.append("preflight.json")
    for fname in input_files:
        p = bundle_dir / fname
        if p.is_file():
            inputs.append({"path": fname, "sha256": _file_sha256(p)})

    invocation = {
        "invocation_id": _gen_invocation_id(),
        "role": "patcher",
        "started_at": started_at,
        "ended_at": ended_at,
        "model": _build_patcher_model_block(patcher_run),
        "prompt": {"path": prompt_path_relative, "sha256": patcher_run["prompt_sha256"]},
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


# ─── reviewer execution ────────────────────────────────────────────────────


REVIEWER_PROMPT_PATH_DEFAULT = Path(__file__).resolve().parents[2] / "prompts" / "reviewer.v9.md"
# Adaptation lane (source-context present, applies_verbatim != true): reviewer.v10
# adds the semantic-equivalence branch to check 0. Verbatim/non-source-backport
# reviews stay on the default (v9).
REVIEWER_PROMPT_PATH_ADAPT = Path(__file__).resolve().parents[2] / "prompts" / "reviewer.v10.md"

# Bounded auto-retry for parse/contract-malformed Reviewer output ONLY (a live
# eval showed the model intermittently, ~33% of the time, drops the required
# '## Equivalence assessment' section in the adaptation lane — transient
# model non-determinism, not a substantive judgment). 2 == one retry.
# Reviewer-only: Patcher and Reproducer are not in scope for this constant.
REVIEWER_MAX_ATTEMPTS = 2


def _reviewer_prompt_relpath(prompt: Path) -> str:
    """Repo-relative path string for `prompt` when it lives under the repo
    (e.g. `prompts/reviewer.v9.md`), else the absolute path. Recorded verbatim
    in replay.json so an override under any directory is faithfully auditable —
    a bare basename would be ambiguous across same-named checked-in prompts."""
    repo_root = Path(__file__).resolve().parents[2]
    resolved = prompt.resolve()
    try:
        return str(resolved.relative_to(repo_root))
    except ValueError:
        return str(resolved)


def _execute_reviewer(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool,
    model_id: str,
    adapter_factory: object | None,
    prompt_path: Path | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Reviewer dispatcher: dispatch-guards, load inputs, run, atomic-write.

    Reviewer reads the same bundle inputs the Patcher had (finding /
    upstream-ref / impact / maintainers / package.nix) PLUS the
    Patcher's outputs (patch.diff and patch-rationale.md).

    Dispatch guards:
      * If the bundle's `kind == "advisory-only"` OR the Patcher
        produced a refusal.json (no patch to review), refuse with
        Reviewer rule 4.
      * Cross-family rule (SPEC §4): if the requested Reviewer model
        belongs to the SAME family as the Patcher invocation already
        recorded in replay.json, refuse with a structured error. The
        attestation in review.md is a model-side acknowledgement; this
        gate is the deterministic enforcement.
    """
    from agents.patcher import AnthropicAdapter
    from agents.reviewer import (
        VALID_EQUIVALENCE_VALUES,
        ReviewerOutputMalformed,
        ReviewerRunResult,
        parse_equivalence_verdict,
        run_reviewer,
    )

    reviewer_prompt = prompt_path or REVIEWER_PROMPT_PATH_DEFAULT
    if not reviewer_prompt.is_file():
        raise ExecutionError(f"reviewer prompt not found: {reviewer_prompt}")

    bundle_path = bundle_dir / "bundle.json"
    if bundle_path.is_file():
        try:
            bundle = json.loads(bundle_path.read_text())
        except Exception as exc:
            raise ExecutionError(f"failed to read bundle.json: {exc}") from exc
        if bundle.get("kind") == "advisory-only":
            raise PatcherDispatchRefused(
                "refuses: bundle.kind=='advisory-only'. Reviewer must not "
                "be invoked on advisory-only bundles (no patch to review)."
            )

    refusal_path = bundle_dir / "refusal.json"
    if refusal_path.is_file():
        raise PatcherDispatchRefused(
            "refuses: bundle declares a refusal.json from the Patcher; "
            "no patch.diff to review. Reviewer dispatch rule 4."
        )

    diff_path = bundle_dir / "patch.diff"
    rat_path = bundle_dir / "patch-rationale.md"
    finding_path = bundle_dir / "finding.json"
    upstream_ref_path = bundle_dir / "upstream-ref.json"
    impact_path = bundle_dir / "impact.json"
    maintainers_path = bundle_dir / "maintainers.json"
    package_path = bundle_dir / "package.nix"
    for p in (diff_path, rat_path, finding_path, upstream_ref_path,
              impact_path, maintainers_path, package_path):
        if not p.is_file():
            raise ExecutionError(
                f"reviewer requires {p.name} in bundle_dir (missing: {p})"
            )

    # Cross-family rule. Read the most recent patcher invocation's
    # model.family from replay.json; if the requested reviewer model
    # would land in the same family, refuse pre-emptively.
    patcher_family = _read_patcher_family_from_replay(bundle_dir)
    requested_family = _model_id_family(model_id)
    if patcher_family and requested_family and patcher_family == requested_family:
        raise ExecutionError(
            f"reviewer model_id={model_id!r} is in the same family "
            f"({requested_family!r}) as the Patcher invocation on file. "
            f"SPEC §4 cross-family rule forbids same-family Patcher/"
            f"Reviewer pairs. Pick a different model family."
        )

    finding = json.loads(finding_path.read_text())
    upstream_ref = json.loads(upstream_ref_path.read_text())
    impact = json.loads(impact_path.read_text())
    maintainers = json.loads(maintainers_path.read_text())
    package_source = package_path.read_text()
    patch_diff = diff_path.read_text()
    patch_rationale_md = rat_path.read_text()

    input_verification: list[dict[str, Any]] = []
    if verify and invocation.get("inputs"):
        for ref in invocation["inputs"]:
            try:
                _raw, _parsed = _load_input(ref, bundle_dir, verify=True)
            except HashMismatch:
                raise
            except ExecutionError:
                raise
            input_verification.append({"path": ref["path"], "verified": True})
    else:
        input_verification = [
            {"path": p.name, "verified": False}
            for p in (finding_path, upstream_ref_path, impact_path,
                      maintainers_path, package_path, diff_path, rat_path)
        ]

    if adapter_factory is not None:
        adapter = adapter_factory(model_id)  # type: ignore[misc]
    else:
        adapter = _build_adapter_from_model_id(model_id, role_label="reviewer")

    # v2 grounding (prompt v1 → v2, DECISIONS 2026-05-19): surface the
    # Patcher's family + Reviewer's own family + the expected
    # rule-honored bit as load-bearing context the model copies
    # verbatim. The deterministic cross-family gate above is independent
    # enforcement; this block is the model-side attestation surface the
    # Reviewer reads into review.md.
    patcher_model_id = _read_patcher_model_id_from_replay(bundle_dir) or "<unknown>"
    rule_honored_expected = bool(
        patcher_family and requested_family and patcher_family != requested_family
    )
    inputs = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_source,
        "package_source_path": package_path.name,
        "patch_diff": patch_diff,
        "patch_rationale_md": patch_rationale_md,
        "model_attestation_context": {
            "reviewer_model_id": model_id,
            "reviewer_family": requested_family or "<unknown>",
            "patcher_model_id": patcher_model_id,
            "patcher_family": patcher_family or "<unknown>",
            "cross_family_rule_honored_expected": rule_honored_expected,
        },
    }

    # Source-backport: give the Reviewer the resolver-supplied upstream fix diff
    # (ground truth) so it can verify the authored backport faithfully
    # transcribes it — rather than checking against a hallucinated notion of the
    # fix. Without this the Reviewer cannot ground a source-backport verdict.
    if (upstream_ref.get("eligibility") or {}).get("patch_strategy") == "source-backport":
        fix_patch_path = bundle_dir / "upstream-fix.patch"
        if not fix_patch_path.is_file():
            raise ExecutionError(
                "reviewer source-backport requires upstream-fix.patch in bundle_dir "
                "(the verdict depends on verifying the authored patch against this "
                "ground-truth diff; refusing to review ungrounded)"
            )
        # Replay integrity: under --verify the recorded invocation must declare
        # upstream-fix.patch, or replay could use a different un-hashed ground truth.
        if verify and invocation.get("inputs") and not any(
            ref.get("path") == "upstream-fix.patch" for ref in invocation["inputs"]
        ):
            raise ExecutionError(
                "reviewer source-backport replay verification: upstream-fix.patch is "
                "not declared in the recorded invocation inputs; refusing to read it "
                "unverified (re-run without --verify to regenerate the invocation)"
            )
        inputs["patch_strategy"] = "source-backport"
        inputs["upstream_fix_patch"] = fix_patch_path.read_text()

        # Adaptation lane (reviewer.v10): a source-context/ dir means the
        # Patcher AUTHORED a semantic adaptation (upstream-fix.patch did not
        # apply verbatim). Feed the Reviewer the pinned pre-patch source + the
        # deterministic applies_verbatim verdict so it judges security-relevant
        # equivalence against the pinned base rather than line-matching the
        # non-applying upstream fix. Route to reviewer.v10 unless the caller
        # pinned an explicit prompt_path (test override).
        sc_dir = bundle_dir / "source-context"
        sc_relpaths = _source_context_relpaths(sc_dir) if sc_dir.is_dir() else []
        preflight_path = bundle_dir / "preflight.json"
        applies_verbatim: bool | None = None
        if preflight_path.is_file():
            try:
                applies_verbatim = json.loads(preflight_path.read_text()).get("applies_verbatim")
            except (json.JSONDecodeError, OSError):
                applies_verbatim = None
        # Only the adaptation lane when source-context carries files AND the fix
        # is NOT verbatim-applicable. A verbatim-applicable source-backport that
        # happens to carry source-context stays on the v9 line-match path.
        if sc_relpaths and applies_verbatim is not True:
            inputs["source_context"] = {
                rel: (sc_dir / rel).read_text() for rel in sc_relpaths
            }
            # We are definitionally NOT in the verbatim lane here (applies_verbatim
            # is not the boolean True). Set the model-facing value to False without
            # truthiness coercion — a malformed non-boolean preflight value (e.g.
            # the JSON string "false") must not be coerced to True and contradict
            # the lane we entered. Fail closed to the adaptation lane, which is the
            # higher-scrutiny path (requires the equivalence assessment).
            inputs["applies_verbatim"] = False
            inputs["model_attestation_context"]["applies_verbatim"] = False

            # Applicability attestation gate (adaptation lane). The Patcher emits
            # patch-applicability.json attesting that the canonical patch.diff was
            # grounded uniquely in source-context and re-applies at fuzz 0. The
            # Reviewer treats it as deterministic evidence that it is reviewing the
            # exact artifact Builder will execute: it MUST be present, its verdicts
            # true, and its canonical hash MUST match the patch.diff on disk (else the
            # patch was swapped after canonicalization). Fail closed at input-assembly
            # time, before any model spend.
            att_path = bundle_dir / "patch-applicability.json"
            if not att_path.is_file():
                raise ExecutionError(
                    "adaptation-lane review requires patch-applicability.json "
                    "(the Patcher's canonical-compile attestation); it is missing — "
                    "refusing to review an unattested adaptation patch"
                )
            try:
                att = json.loads(att_path.read_text())
            except json.JSONDecodeError as exc:
                raise ExecutionError(
                    f"patch-applicability.json is not valid JSON: {exc}"
                ) from exc
            # Fail closed on a tampered non-object attestation (valid JSON that
            # is `[]`, `null`, a string, etc.): `.get()` on a non-dict would
            # raise AttributeError and escape the CLI's controlled rejection.
            if not isinstance(att, dict):
                raise ExecutionError(
                    "patch-applicability.json must be a JSON object; got "
                    f"{type(att).__name__} — refusing to review a malformed / "
                    "tampered attestation"
                )
            if att.get("applies_at_fuzz0") is not True or att.get(
                "unique_source_match"
            ) is not True:
                raise ExecutionError(
                    "patch-applicability.json attests the patch does not apply at "
                    "fuzz 0 / is not uniquely grounded — refusing adaptation review"
                )
            actual_diff_sha = sha256_hex(diff_path.read_bytes())
            if att.get("canonical_patch_sha256") != actual_diff_sha:
                raise ExecutionError(
                    "patch-applicability.json canonical_patch_sha256 does not match "
                    "patch.diff on disk — the reviewed patch is not the attested "
                    "artifact (tamper / stale attestation); refusing review"
                )
            inputs["model_attestation_context"]["patch_applicability"] = att
            if verify and invocation.get("inputs"):
                if "patch-applicability.json" not in {
                    ref.get("path") for ref in invocation["inputs"]
                }:
                    raise ExecutionError(
                        "reviewer replay: patch-applicability.json not declared in the "
                        "recorded invocation inputs; refusing to read it unverified"
                    )
            if "patch-applicability.json" not in {v.get("path") for v in input_verification}:
                input_verification.append(
                    {"path": "patch-applicability.json", "verified": False}
                )

            if prompt_path is None:
                reviewer_prompt = REVIEWER_PROMPT_PATH_ADAPT

            # Replay integrity: a recorded v10 invocation MUST declare the
            # source-context files (+ preflight.json) as inputs, or replay could
            # judge equivalence against different/absent source.
            if verify and invocation.get("inputs"):
                declared = {ref.get("path") for ref in invocation["inputs"]}
                need = {f"source-context/{rel}" for rel in sc_relpaths}
                if preflight_path.is_file():
                    need.add("preflight.json")
                missing = sorted(need - declared)
                if missing:
                    raise ExecutionError(
                        "reviewer source-context replay verification: "
                        f"{missing} not declared in the recorded invocation inputs; "
                        "refusing to read them unverified (re-run without --verify)"
                    )
            _already = {v.get("path") for v in input_verification}
            for rel in sc_relpaths:
                key = f"source-context/{rel}"
                if key not in _already:
                    input_verification.append({"path": key, "verified": False})
            if preflight_path.is_file() and "preflight.json" not in _already:
                input_verification.append({"path": "preflight.json", "verified": False})

    def _attempt_once() -> ReviewerRunResult:
        """Call the model once, parse, and enforce the adaptation-lane
        contract. Returns a conformant ReviewerRunResult, or raises
        ReviewerOutputMalformed — either the parser's own exception (run_
        reviewer, malformed sections/headings) or the adaptation-lane
        equivalence-assessment violation constructed below. Raising both
        as the same exception type lets the retry loop below treat them
        identically."""
        candidate = run_reviewer(
            inputs=inputs,
            adapter=adapter,
            prompt_path=reviewer_prompt,
            sampling=({"max_tokens": max_tokens} if max_tokens is not None else None),
        )

        # Adaptation-lane contract enforcement (reviewer.v10). In this lane the
        # `## Equivalence assessment` section REPLACES the line-level `## Patch
        # comparison` as the check-0 gate, so an `accept` that omits it has no
        # semantic-equivalence evidence. Enforce contextually here (the parser is
        # applies_verbatim-agnostic; the executor is not). Parse-before-write: nothing
        # is on disk yet, so a violation aborts cleanly. `inputs["source_context"]`
        # is set only when the adaptation lane was entered.
        if inputs.get("source_context") and candidate.kind == "review":
            ea = candidate.parsed.equivalence_assessment_raw
            problem: str | None = None
            # Extract the DECLARED equivalence value exactly (not a substring test): the
            # section's line reads `equivalence: <value> — <why>`. A substring check
            # would miss `accept` paired with `indeterminate` (missing evidence, must
            # escalate) and would tolerate arbitrary values like `equivalence: unknown`.
            # Shared with the cohort-eval adaptation-equivalence scorer so the two
            # can never drift.
            equivalence_value = parse_equivalence_verdict(ea)
            valid_equivalence = set(VALID_EQUIVALENCE_VALUES)
            if not ea or equivalence_value is None:
                problem = (
                    "adaptation-lane review (applies_verbatim=false) must include a "
                    "'## Equivalence assessment' section with an 'equivalence:' line — "
                    "it is the check-0 gate that replaces line-level matching"
                )
            elif equivalence_value not in valid_equivalence:
                problem = (
                    f"adaptation-lane review has an unrecognized equivalence value "
                    f"{equivalence_value!r} (expected equivalent | not-equivalent | "
                    f"indeterminate)"
                )
            elif candidate.parsed.verdict == "accept" and equivalence_value != "equivalent":
                problem = (
                    f"adaptation-lane review verdict is 'accept' but equivalence is "
                    f"{equivalence_value!r} — accept requires 'equivalent'; "
                    f"'not-equivalent' and 'indeterminate' (missing evidence) must escalate"
                )
            if problem:
                exc2 = ReviewerOutputMalformed(problem)
                setattr(exc2, "raw_response", candidate.parsed.raw_review_md or "")
                # Carry this attempt's response so its token usage is billed
                # even though it parsed cleanly (site-1 attaches it in run_reviewer).
                setattr(exc2, "model_response", candidate.model_response)
                raise exc2
        return candidate

    # Bounded auto-retry (REVIEWER_MAX_ATTEMPTS). Retry ONLY parse/contract-
    # malformed output — transient model non-determinism, not a substantive
    # outcome. A valid refusal or a valid review (any verdict, including
    # reject) is a SUCCESS on the first attempt that returns immediately.
    # Every failed attempt is still persisted via _persist_role_failure before
    # the loop retries or gives up, so a retry that succeeds never erases the
    # evidence that an earlier attempt was non-conformant.
    started_at = _utc_now_iso()
    result: ReviewerRunResult | None = None
    reviewer_attempts = 0
    # Each failed attempt still spent API tokens; collect their responses so
    # the sidecar can bill TOTAL realized spend, not just the conforming run.
    failed_responses: list[Any] = []
    for attempt in range(1, REVIEWER_MAX_ATTEMPTS + 1):
        reviewer_attempts = attempt
        try:
            result = _attempt_once()
            break
        except ReviewerOutputMalformed as exc:
            _persist_role_failure(
                role="reviewer",
                bundle_dir=bundle_dir,
                exc=exc,
                model_id=model_id,
                started_at=started_at,
                prompt_path_relative=_reviewer_prompt_relpath(reviewer_prompt),
            )
            # A pre-parser failure (raised before the model call) has no
            # response; guard so we only bill attempts that reached the model.
            mr = getattr(exc, "model_response", None)
            if mr is not None:
                failed_responses.append(mr)
            if attempt >= REVIEWER_MAX_ATTEMPTS:
                raise ExecutionError(f"reviewer output malformed: {exc}") from exc
            # else: attempts remain, loop retries. The retry is the fix for
            # the ~33% transient equivalence-assessment / parse flake this
            # constant was added for.
    ended_at = _utc_now_iso()
    assert result is not None  # loop above only exits via break or raise

    # First-attempt conformance is a SEPARATE metric from the retried outcome
    # above: a successful retry must not erase the fact that attempt 1 was
    # non-conformant. Surfaced in reviewer_run_meta below and copied into the
    # invocation sidecar by _write_role_invocation_sidecar.
    first_attempt_conformant = reviewer_attempts == 1
    retry_count = reviewer_attempts - 1

    outputs: list[dict[str, Any]] = []
    if result.kind == "review":
        review_md = result.parsed.raw_review_md or ""
        review_bytes = review_md.encode("utf-8")
        if review_bytes and not review_bytes.endswith(b"\n"):
            review_bytes += b"\n"
        _atomic_write_bytes(bundle_dir / "review.md", review_bytes)
        outputs = [{
            "path": "review.md", "sha256": sha256_hex(review_bytes),
            "bytes": len(review_bytes),
        }]
    else:  # refusal
        refusal_body = json.dumps(
            {"rule": result.parsed.refusal_rule, "reason": result.parsed.refusal_reason},
            indent=2, sort_keys=True,
        ).encode("utf-8") + b"\n"
        _atomic_write_bytes(bundle_dir / "review-refusal.json", refusal_body)
        outputs = [{
            "path": "review-refusal.json", "sha256": sha256_hex(refusal_body),
            "bytes": len(refusal_body),
        }]

    # v2 attestation validator (DECISIONS 2026-05-19 corpus-saturation +
    # Reviewer-validator entry). Compare the Reviewer's emitted
    # Cross-family attestation fields against the executor-supplied
    # Model attestation context block. Mismatches are flagged in
    # reviewer_run_meta and in validators_passed; they are not blocking
    # (the deterministic cross-family gate already enforces pairing) but
    # they surface prompt-accuracy failures for downstream scoring.
    mac = inputs.get("model_attestation_context") or {}
    expected_reviewer_family = mac.get("reviewer_family", "<unknown>")
    expected_patcher_family = mac.get("patcher_family", "<unknown>")
    emitted_cf = result.parsed.cross_family
    attestation_grounded: bool | None = None
    if emitted_cf and expected_reviewer_family != "<unknown>":
        reviewer_match = (emitted_cf.reviewer_family == expected_reviewer_family)
        patcher_match = (emitted_cf.patcher_family_observed == expected_patcher_family)
        attestation_grounded = reviewer_match and patcher_match

    reviewer_run_meta: dict[str, Any] = {
        "prompt_sha256": result.prompt_sha256,
        "user_content_sha256": result.user_content_sha256,
        "raw_response_sha256": result.raw_response_sha256,
        "model_id": result.model_response.model_id,
        "sampling": result.sampling,
        "kind": result.kind,
        "verdict": result.parsed.verdict,
        "refusal_rule": result.parsed.refusal_rule,
        "refusal_reason": result.parsed.refusal_reason,
        "adapter": result.model_response.extras.get("adapter"),
        # v2 attestation: were the Cross-family attestation fields copied
        # verbatim from the Model attestation context block? None when the
        # context block was unavailable (e.g. pre-v2 callers).
        "attestation_grounded": attestation_grounded,
        # Bounded auto-retry metrics (REVIEWER_MAX_ATTEMPTS). first_attempt_
        # conformant is a separate claim from the (possibly retried) success
        # above — see the comment at the retry loop.
        "first_attempt_conformant": first_attempt_conformant,
        "retry_count": retry_count,
        "reviewer_attempts": reviewer_attempts,
    }

    replay_invocation = _build_reviewer_invocation(
        bundle_dir=bundle_dir,
        reviewer_run=reviewer_run_meta,
        outputs=outputs,
        started_at=started_at,
        ended_at=ended_at,
        prompt_path_relative=_reviewer_prompt_relpath(reviewer_prompt),
    )

    # Sidecar BEFORE replay-append: model spend has happened; if the
    # replay-append fails (e.g. missing replay.json on a fresh-bundle
    # path) we still want the cost captured so the auditor can
    # reconcile spend.
    _write_role_invocation_sidecar(
        bundle_dir=bundle_dir,
        role="reviewer",
        cve_id=_read_bundle_cve_id(bundle_dir),
        invocation_id=replay_invocation["invocation_id"],
        started_at=started_at,
        ended_at=ended_at,
        role_run_meta=reviewer_run_meta,
        model_response=result.model_response,
        # Bill any earlier malformed attempts' usage into total realized spend.
        extra_usages=failed_responses,
    )

    _append_reviewer_replay_entry(
        bundle_dir=bundle_dir, invocation=replay_invocation,
    )

    return {
        "role": "reviewer",
        "invocation_id": replay_invocation["invocation_id"],
        "kind": result.kind,
        "verdict": result.parsed.verdict,
        "outputs": outputs,
        "input_verification": input_verification,
        "verified": verify,
        "reviewer_run": reviewer_run_meta,
        "replay_invocation": replay_invocation,
    }


def _model_id_family(model_id: str) -> str | None:
    """Map a model_id to a coarse family string. Mirrors
    _build_patcher_model_block's logic so the cross-family check sees the
    same labels both sides."""
    if model_id.startswith("claude-opus"):
        return "anthropic-opus"
    if model_id.startswith("claude-sonnet"):
        return "anthropic-sonnet"
    if model_id.startswith("claude-haiku"):
        return "anthropic-haiku"
    if model_id.startswith("claude-"):
        return "anthropic-other"
    if model_id.startswith("gpt-") or model_id.startswith("o1-") or model_id.startswith("o3-"):
        return "openai-gpt"
    return None


def _build_adapter_from_model_id(model_id: str, *, role_label: str):
    """Resolve a model_id to a concrete adapter.

    Single source of truth for all three model-backed roles. claude-*
    routes to AnthropicAdapter; gpt-* / o1-* / o3-* route to
    OpenAIAdapter (which honors OPENAI_BASE_URL for vLLM / OpenRouter
    / any OpenAI-compatible server).

    Tests inject FakeAdapter via the role's adapter_factory parameter
    and bypass this helper entirely.
    """
    from agents.patcher import AnthropicAdapter, OpenAIAdapter

    if model_id.startswith("claude-"):
        return AnthropicAdapter(model_id)
    if (
        model_id.startswith("gpt-")
        or model_id.startswith("o1-")
        or model_id.startswith("o3-")
    ):
        return OpenAIAdapter(model_id)
    raise ExecutionError(
        f"no adapter wired for {role_label} model id {model_id!r}. "
        f"Supply an adapter_factory, or pass a claude-* / gpt-* / "
        f"o1-* / o3-* model id."
    )


def _read_patcher_family_from_replay(bundle_dir: Path) -> str | None:
    """Inspect replay.json for the most recent patcher invocation's
    declared family; returns None if no patcher invocation is recorded."""
    model_id = _read_patcher_model_id_from_replay(bundle_dir)
    if model_id is None:
        return None
    return _model_id_family(model_id)


def _read_patcher_model_id_from_replay(bundle_dir: Path) -> str | None:
    """Inspect replay.json for the most recent patcher invocation's
    declared model_id; returns None if no patcher invocation is
    recorded. Used by the Reviewer wiring to surface the load-bearing
    Model attestation context block in v2."""
    rj = bundle_dir / "replay.json"
    if not rj.is_file():
        return None
    try:
        replay = json.loads(rj.read_text())
    except json.JSONDecodeError:
        return None
    for role in replay.get("roles", []):
        if role.get("role") != "patcher":
            continue
        invs = role.get("invocations", [])
        if not invs:
            continue
        last = invs[-1]
        return (last.get("model") or {}).get("model_id") or None
    return None


def _build_reviewer_invocation(
    *,
    bundle_dir: Path,
    reviewer_run: dict[str, Any],
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
    prompt_path_relative: str = f"prompts/{REVIEWER_PROMPT_PATH_DEFAULT.name}",
) -> dict[str, Any]:
    """Build a single replay-shape invocation record for a Reviewer run."""
    inputs: list[dict[str, Any]] = []
    review_input_files = ["finding.json", "upstream-ref.json", "impact.json",
                          "maintainers.json", "package.nix",
                          "patch.diff", "patch-rationale.md"]
    # On the source-backport path the verdict depends on upstream-fix.patch
    # (the ground truth the Reviewer verifies against), so it is replay-critical.
    if (bundle_dir / "upstream-fix.patch").is_file():
        review_input_files.append("upstream-fix.patch")
    # Adaptation lane (reviewer.v10): the equivalence verdict is grounded in the
    # pinned source-context/ + the preflight verdict, so both are replay-critical
    # reviewer inputs — a replay must judge the same bytes. Only recorded when the
    # v10 lane was actually entered (preflight.applies_verbatim != true).
    sc_dir = bundle_dir / "source-context"
    if sc_dir.is_dir():
        pf = bundle_dir / "preflight.json"
        av = None
        if pf.is_file():
            try:
                av = json.loads(pf.read_text()).get("applies_verbatim")
            except (json.JSONDecodeError, OSError):
                av = None
        sc_rels = _source_context_relpaths(sc_dir)
        if sc_rels and av is not True:
            review_input_files += [f"source-context/{rel}" for rel in sc_rels]
            if pf.is_file():
                review_input_files.append("preflight.json")
            # The applicability attestation is deterministic evidence the Reviewer
            # gates on (canonical patch applies at fuzz 0, matches patch.diff), so a
            # replay must judge against the same attestation → replay-critical.
            if (bundle_dir / "patch-applicability.json").is_file():
                review_input_files.append("patch-applicability.json")
    for fname in review_input_files:
        p = bundle_dir / fname
        if p.is_file():
            inputs.append({"path": fname, "sha256": _file_sha256(p)})
    invocation = {
        "invocation_id": _gen_invocation_id(),
        "role": "reviewer",
        "started_at": started_at,
        "ended_at": ended_at,
        "model": _build_reviewer_model_block(reviewer_run),
        "prompt": {"path": prompt_path_relative, "sha256": reviewer_run["prompt_sha256"]},
        "inputs": inputs,
        "outputs": [{"path": o["path"], "sha256": o["sha256"]} for o in outputs],
        "rng_seed": None,
        "validators_passed": _reviewer_validators_for(reviewer_run),
        "network_policy_applied": "none",
    }
    return invocation


def _build_reviewer_model_block(reviewer_run: dict[str, Any]) -> dict[str, Any]:
    """Reviewer model block. Uses the Patcher's helper since the family-
    derivation rules are identical."""
    return _build_patcher_model_block({
        "model_id": reviewer_run["model_id"],
        "sampling": reviewer_run.get("sampling") or {},
        "adapter": reviewer_run.get("adapter") or "unknown",
    })


def _reviewer_validators_for(reviewer_run: dict[str, Any]) -> list[str]:
    if reviewer_run.get("kind") == "refusal":
        return ["refusal-shape"]
    validators = ["schema-valid-output"]
    grounded = reviewer_run.get("attestation_grounded")
    if grounded is True:
        validators.append("attestation-grounded")
    elif grounded is False:
        validators.append("attestation-mismatch")
    # grounded is None → pre-v2 caller, no attestation context surfaced; omit
    return validators


def _append_reviewer_replay_entry(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
) -> None:
    """Append a Reviewer invocation into replay.json's roles[]."""
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        raise ExecutionError(
            f"replay.json missing in {bundle_dir}; reviewer requires a "
            f"pre-existing replay.json (the patcher invocation that "
            f"produced patch.diff is its anchor)."
        )
    replay = json.loads(replay_path.read_text())
    roles = replay.setdefault("roles", [])
    role_entry = None
    for r in roles:
        if r.get("role") == "reviewer":
            role_entry = r
            break
    if role_entry is None:
        role_entry = {"role": "reviewer", "invocations": []}
        roles.append(role_entry)
    role_entry["invocations"].append(invocation)
    body = json.dumps(replay, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_bytes(replay_path, body.encode("utf-8"))


# ─── reproducer execution ──────────────────────────────────────────────────


REPRODUCER_PROMPT_PATH_DEFAULT = (
    Path(__file__).resolve().parents[2] / "prompts" / "reproducer.v16.md"
)

# Bundle-local PoC artifact surfacing (DECISIONS 2026-05-19 (Reproducer v5)):
# the Reproducer's user message now includes a "Bundle-local PoC artifacts"
# section listing files under bundle_dir/repro/. Caps protect against
# pathological inputs. Codex peer ack on these specific values.
POC_PER_FILE_INLINE_CAP = 4096
POC_TOTAL_INLINE_CAP = 32768
POC_MAX_COUNT = 16
POC_PREVIEW_BYTES = 256


def _collect_bundle_local_pocs(bundle_dir: Path) -> list[dict[str, Any]]:
    """Enumerate bundle_dir/repro/ for Reproducer-visible PoC artifacts.

    Returns a list of dicts, one per file. Shape:
      {
        "path": "repro/crash_poc.csm",        # POSIX relative
        "sha256": "<hex>",
        "size_bytes": <int>,
        "kind": "text" | "binary",
        "inline": <bool>,                      # true iff size <= POC_PER_FILE_INLINE_CAP
        "content_base64": "<b64>" | None,      # iff inline AND binary
        "content_text": "<str>" | None,        # iff inline AND text
        "preview_base64_first_256": "<b64>" | None,   # iff NOT inline
        "preview_base64_last_256": "<b64>" | None,    # iff NOT inline
      }

    Refuses:
      * symlinks (silently skipped with skip_reason='symlink-rejected')
      * paths containing '..' or absolute paths (skip_reason='path-rejected')
      * hidden files (.*) (skip_reason='hidden-file-rejected')
      * more than POC_MAX_COUNT files (extra items skipped with skip_reason='count-cap-exceeded')
      * total inline bytes exceeding POC_TOTAL_INLINE_CAP (later files lose inline content,
        retain path+sha256+size)

    Skipped entries are returned with skip_reason set instead of content fields,
    so the Reproducer prompt sees the path was considered and rejected.
    """
    import base64
    import hashlib

    repro_dir = bundle_dir / "repro"
    if not repro_dir.is_dir():
        return []

    candidates: list[Path] = []
    skipped: list[dict[str, Any]] = []
    for p in sorted(repro_dir.rglob("*")):
        if not p.exists() or p.is_dir():
            continue
        # symlink check first — Path.is_symlink() works even when target missing
        if p.is_symlink():
            skipped.append({
                "path": _safe_relpath(p, bundle_dir),
                "skip_reason": "symlink-rejected",
            })
            continue
        # Reject anything that doesn't normalize cleanly back into bundle_dir/repro
        try:
            rel = p.resolve().relative_to(repro_dir.resolve())
        except ValueError:
            skipped.append({
                "path": _safe_relpath(p, bundle_dir),
                "skip_reason": "path-rejected",
            })
            continue
        # Hidden / dotfile rejection
        if any(part.startswith(".") for part in rel.parts):
            skipped.append({
                "path": _safe_relpath(p, bundle_dir),
                "skip_reason": "hidden-file-rejected",
            })
            continue
        candidates.append(p)

    # Apply count cap.
    accepted: list[dict[str, Any]] = []
    total_inline_bytes = 0
    for idx, p in enumerate(candidates):
        if idx >= POC_MAX_COUNT:
            accepted.append({
                "path": f"repro/{p.relative_to(repro_dir).as_posix()}",
                "skip_reason": "count-cap-exceeded",
            })
            continue
        try:
            data = p.read_bytes()
        except OSError as exc:
            accepted.append({
                "path": f"repro/{p.relative_to(repro_dir).as_posix()}",
                "skip_reason": f"read-error: {exc.strerror}",
            })
            continue
        sha = hashlib.sha256(data).hexdigest()
        size = len(data)
        # Heuristic: assume "text" if entire content decodes UTF-8 without
        # control characters (other than common whitespace). Otherwise binary.
        is_text = _looks_textual(data)
        entry: dict[str, Any] = {
            "path": f"repro/{p.relative_to(repro_dir).as_posix()}",
            "sha256": sha,
            "size_bytes": size,
            "kind": "text" if is_text else "binary",
        }
        if size <= POC_PER_FILE_INLINE_CAP and total_inline_bytes + size <= POC_TOTAL_INLINE_CAP:
            entry["inline"] = True
            total_inline_bytes += size
            if is_text:
                entry["content_text"] = data.decode("utf-8", errors="replace")
            else:
                entry["content_base64"] = base64.b64encode(data).decode("ascii")
        else:
            entry["inline"] = False
            entry["preview_base64_first_256"] = base64.b64encode(data[:POC_PREVIEW_BYTES]).decode("ascii")
            entry["preview_base64_last_256"] = base64.b64encode(data[-POC_PREVIEW_BYTES:]).decode("ascii")
        accepted.append(entry)

    return accepted + skipped


def _safe_relpath(p: Path, base: Path) -> str:
    """Best-effort POSIX-relative path string for a skipped entry. Falls
    back to the basename if relative_to() fails (e.g. symlink outside base)."""
    try:
        return p.relative_to(base).as_posix()
    except ValueError:
        return p.name


def _looks_textual(data: bytes) -> bool:
    """Heuristic: treat as 'text' if UTF-8-decodable with mostly printable
    characters (control characters limited to tab, newline, CR). Used only
    to choose between inlining as content_text vs content_base64; the
    sha256 + size are the load-bearing fields."""
    if not data:
        return True
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    allowed_controls = {"\t", "\n", "\r"}
    bad = sum(1 for ch in s if ord(ch) < 32 and ch not in allowed_controls)
    return bad <= len(s) // 50  # ≤ 2% control noise tolerable


def _execute_reproducer(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool,
    model_id: str,
    adapter_factory: object | None,
) -> dict[str, Any]:
    """Reproducer dispatcher: dispatch-guards, load inputs, run, atomic-write.

    Reproducer reads the same bundle inputs the Reviewer had (finding /
    upstream-ref / impact / maintainers / package.nix / patch.diff /
    patch-rationale.md). It does NOT touch build.json — that's strictly
    Builder's territory per the 2026-04-28 architectural split.

    Dispatch guards:
      * If the bundle's `kind == "advisory-only"` OR the Patcher
        produced a refusal.json (no patch to reproduce), refuse with
        Reproducer rule 1 / rule 2.
      * Cross-family rule (b2b3b2c): if the requested Reproducer model
        belongs to the SAME family as the Patcher invocation already
        recorded in replay.json, refuse with a structured error. The
        executor enforces; the model's own attestation is theatrical
        (proven fabricated under sonnet across three reviewer runs).
    """
    from agents.patcher import AnthropicAdapter
    from agents.reproducer import ReproducerOutputMalformed, run_reproducer

    bundle_path = bundle_dir / "bundle.json"
    if bundle_path.is_file():
        try:
            bundle = json.loads(bundle_path.read_text())
        except Exception as exc:
            raise ExecutionError(f"failed to read bundle.json: {exc}") from exc
        if bundle.get("kind") == "advisory-only":
            raise PatcherDispatchRefused(
                "refuses: bundle.kind=='advisory-only'. Reproducer must not "
                "be invoked on advisory-only bundles (no patch to reproduce)."
            )

    refusal_path = bundle_dir / "refusal.json"
    if refusal_path.is_file():
        raise PatcherDispatchRefused(
            "refuses: bundle declares a refusal.json from the Patcher; "
            "no patch.diff to reproduce. Reproducer dispatch rule 1."
        )

    diff_path = bundle_dir / "patch.diff"
    rat_path = bundle_dir / "patch-rationale.md"
    finding_path = bundle_dir / "finding.json"
    upstream_ref_path = bundle_dir / "upstream-ref.json"
    impact_path = bundle_dir / "impact.json"
    maintainers_path = bundle_dir / "maintainers.json"
    package_path = bundle_dir / "package.nix"
    for p in (diff_path, rat_path, finding_path, upstream_ref_path,
              impact_path, maintainers_path, package_path):
        if not p.is_file():
            raise ExecutionError(
                f"reproducer requires {p.name} in bundle_dir (missing: {p})"
            )

    # Cross-family rule. Read the most recent patcher invocation's
    # model.family from replay.json; if the requested reproducer model
    # would land in the same family, refuse pre-emptively.
    patcher_family = _read_patcher_family_from_replay(bundle_dir)
    requested_family = _model_id_family(model_id)
    if patcher_family and requested_family and patcher_family == requested_family:
        raise ExecutionError(
            f"reproducer model_id={model_id!r} is in the same family "
            f"({requested_family!r}) as the Patcher invocation on file. "
            f"The Reproducer cross-family rule (DECISIONS 2026-04-28) "
            f"forbids same-family Patcher/Reproducer pairs. Pick a "
            f"different model family."
        )

    finding = json.loads(finding_path.read_text())
    upstream_ref = json.loads(upstream_ref_path.read_text())
    impact = json.loads(impact_path.read_text())
    maintainers = json.loads(maintainers_path.read_text())
    package_source = package_path.read_text()
    patch_diff = diff_path.read_text()
    patch_rationale_md = rat_path.read_text()

    input_verification: list[dict[str, Any]] = []
    if verify and invocation.get("inputs"):
        for ref in invocation["inputs"]:
            try:
                _raw, _parsed = _load_input(ref, bundle_dir, verify=True)
            except HashMismatch:
                raise
            except ExecutionError:
                raise
            input_verification.append({"path": ref["path"], "verified": True})
    else:
        input_verification = [
            {"path": p.name, "verified": False}
            for p in (finding_path, upstream_ref_path, impact_path,
                      maintainers_path, package_path, diff_path, rat_path)
        ]

    if adapter_factory is not None:
        adapter = adapter_factory(model_id)  # type: ignore[misc]
    else:
        adapter = _build_adapter_from_model_id(model_id, role_label="reproducer")

    # v5 grounding (prompt v4 → v5, DECISIONS 2026-05-19 (Reproducer v5)):
    # surface bundle-local PoC artifacts under bundle_dir/repro/ as a
    # new "Bundle-local PoC artifacts" section in the user message. Caps,
    # symlink rejection, traversal rejection, and the path+sha256 form
    # for oversized files match the codex-peer-acked design.
    pocs = _collect_bundle_local_pocs(bundle_dir)

    inputs = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_source,
        "package_source_path": package_path.name,
        "patch_diff": patch_diff,
        "patch_rationale_md": patch_rationale_md,
        "bundle_local_pocs": pocs,
    }

    started_at = _utc_now_iso()
    try:
        result = run_reproducer(
            inputs=inputs,
            adapter=adapter,
            prompt_path=REPRODUCER_PROMPT_PATH_DEFAULT,
        )
    except ReproducerOutputMalformed as exc:
        _persist_role_failure(
            role="reproducer",
            bundle_dir=bundle_dir,
            exc=exc,
            model_id=model_id,
            started_at=started_at,
            prompt_path_relative=f"prompts/{REPRODUCER_PROMPT_PATH_DEFAULT.name}",
        )
        raise ExecutionError(f"reproducer output malformed: {exc}") from exc
    ended_at = _utc_now_iso()

    outputs: list[dict[str, Any]] = []
    if result.kind == "reproducer":
        # Three files + atomic write + trailing-newline guarantee
        # (mirrors patcher's defensive newline rule).
        nix_bytes = (result.parsed.raw_reproducer_nix or "").encode("utf-8")
        log_bytes = (result.parsed.raw_reproducer_log_txt or "").encode("utf-8")
        json_bytes = (result.parsed.raw_passthru_tests_json or "").encode("utf-8")
        for buf_name, buf in (
            ("reproducer.nix", nix_bytes),
            ("reproducer-log.txt", log_bytes),
            ("passthru-tests.json", json_bytes),
        ):
            if buf and not buf.endswith(b"\n"):
                buf = buf + b"\n"
            _atomic_write_bytes(bundle_dir / buf_name, buf)
            outputs.append({
                "path": buf_name,
                "sha256": sha256_hex(buf),
                "bytes": len(buf),
            })
    else:  # refusal
        refusal_body = json.dumps(
            {"rule": result.parsed.refusal_rule,
             "reason": result.parsed.refusal_reason},
            indent=2, sort_keys=True,
        ).encode("utf-8") + b"\n"
        _atomic_write_bytes(bundle_dir / "reproducer-refusal.json", refusal_body)
        outputs = [{
            "path": "reproducer-refusal.json",
            "sha256": sha256_hex(refusal_body),
            "bytes": len(refusal_body),
        }]

    reproducer_run_meta: dict[str, Any] = {
        "prompt_sha256": result.prompt_sha256,
        "user_content_sha256": result.user_content_sha256,
        "raw_response_sha256": result.raw_response_sha256,
        "model_id": result.model_response.model_id,
        "sampling": result.sampling,
        "kind": result.kind,
        "is_proxy": result.parsed.is_proxy,
        "refusal_rule": result.parsed.refusal_rule,
        "refusal_reason": result.parsed.refusal_reason,
        "adapter": result.model_response.extras.get("adapter"),
    }

    replay_invocation = _build_reproducer_invocation(
        bundle_dir=bundle_dir,
        reproducer_run=reproducer_run_meta,
        outputs=outputs,
        started_at=started_at,
        ended_at=ended_at,
        patcher_family_recorded=patcher_family,
    )

    # Sidecar BEFORE replay-append: cost data is captured even if
    # replay-append later raises.
    _write_role_invocation_sidecar(
        bundle_dir=bundle_dir,
        role="reproducer",
        cve_id=_read_bundle_cve_id(bundle_dir),
        invocation_id=replay_invocation["invocation_id"],
        started_at=started_at,
        ended_at=ended_at,
        role_run_meta=reproducer_run_meta,
        model_response=result.model_response,
    )

    _append_reproducer_replay_entry(
        bundle_dir=bundle_dir, invocation=replay_invocation,
    )

    return {
        "role": "reproducer",
        "invocation_id": replay_invocation["invocation_id"],
        "kind": result.kind,
        "is_proxy": result.parsed.is_proxy,
        "outputs": outputs,
        "input_verification": input_verification,
        "verified": verify,
        "reproducer_run": reproducer_run_meta,
        "replay_invocation": replay_invocation,
    }


def _build_reproducer_invocation(
    *,
    bundle_dir: Path,
    reproducer_run: dict[str, Any],
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
    patcher_family_recorded: str | None,
) -> dict[str, Any]:
    """Build a single replay-shape invocation record for a Reproducer run.

    Adds two fields beyond the standard reviewer/patcher shape, per
    `docs/REPRODUCER_V1.md` §8:

      * `patcher_invocation_id` — points at the patcher invocation
        whose patch.diff this reproducer is verifying. Surfaces the
        cross-role pairing in the replay record.
      * `patcher_family_recorded` — the family the executor resolved
        from that patcher invocation, used to enforce the cross-family
        rule. Recorded so an auditor can verify the pair was honored
        without re-resolving the family from model_id.

    `cross_family_rule_honored: true` is set unconditionally because
    the executor refuses pre-emptively when the rule would be violated;
    arrival at this builder implies the check passed.
    """
    inputs: list[dict[str, Any]] = []
    for fname in (
        "finding.json", "upstream-ref.json", "impact.json",
        "maintainers.json", "package.nix",
        "patch.diff", "patch-rationale.md",
    ):
        p = bundle_dir / fname
        if p.is_file():
            inputs.append({"path": fname, "sha256": _file_sha256(p)})

    invocation = {
        "invocation_id": _gen_invocation_id(),
        "role": "reproducer",
        "started_at": started_at,
        "ended_at": ended_at,
        "model": _build_reproducer_model_block(reproducer_run),
        "prompt": {
            "path": f"prompts/{REPRODUCER_PROMPT_PATH_DEFAULT.name}",
            "sha256": reproducer_run["prompt_sha256"],
        },
        "inputs": inputs,
        "outputs": [{"path": o["path"], "sha256": o["sha256"]} for o in outputs],
        "patcher_invocation_id": _read_latest_patcher_invocation_id(bundle_dir),
        "patcher_family_recorded": patcher_family_recorded,
        "cross_family_rule_honored": True,
        "rng_seed": None,
        "validators_passed": _reproducer_validators_for(reproducer_run),
        "network_policy_applied": "none",
    }
    return invocation


def _build_reproducer_model_block(reproducer_run: dict[str, Any]) -> dict[str, Any]:
    """Reproducer model block. Reuses the patcher model-block helper
    because family-derivation rules are identical."""
    return _build_patcher_model_block({
        "model_id": reproducer_run["model_id"],
        "sampling": reproducer_run.get("sampling") or {},
        "adapter": reproducer_run.get("adapter") or "unknown",
    })


def _reproducer_validators_for(reproducer_run: dict[str, Any]) -> list[str]:
    if reproducer_run.get("kind") == "refusal":
        return ["refusal-shape"]
    return ["schema-valid-output"]


def _read_latest_patcher_invocation_id(bundle_dir: Path) -> str | None:
    """Return the invocation_id of the most recent patcher run, if any."""
    rj = bundle_dir / "replay.json"
    if not rj.is_file():
        return None
    try:
        replay = json.loads(rj.read_text())
    except json.JSONDecodeError:
        return None
    for role in replay.get("roles", []):
        if role.get("role") != "patcher":
            continue
        invs = role.get("invocations", [])
        if not invs:
            continue
        return invs[-1].get("invocation_id")
    return None


def _append_reproducer_replay_entry(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
) -> None:
    """Append a Reproducer invocation into replay.json's roles[]."""
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        raise ExecutionError(
            f"replay.json missing in {bundle_dir}; reproducer requires a "
            f"pre-existing replay.json (the patcher invocation that "
            f"produced patch.diff is its anchor)."
        )
    replay = json.loads(replay_path.read_text())
    roles = replay.setdefault("roles", [])
    role_entry = None
    for r in roles:
        if r.get("role") == "reproducer":
            role_entry = r
            break
    if role_entry is None:
        role_entry = {"role": "reproducer", "invocations": []}
        roles.append(role_entry)
    role_entry["invocations"].append(invocation)
    body = json.dumps(replay, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_bytes(replay_path, body.encode("utf-8"))


def record_sampled_reproducer_invocation(
    *,
    bundle_dir: Path,
    winning_run: Any,
    billed_runs: tuple[Any, ...],
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
) -> dict[str, Any] | None:
    """Record a pass@K winner as a first-class Reproducer invocation.

    Gives verifier-guided sampling provenance PARITY with the single-shot
    executor: appends a standard reproducer invocation to replay.json's
    roles[] and writes the reproducer-invocation.json cost sidecar, exactly
    as `_execute_reproducer` does for a single-shot run. The invocation shape
    is intentionally identical (no schema change) — the full pass@K story
    (k, per-draw verdicts, winner temperature, verifier) lives in the signed
    `reproducer-sampling.json`. This invocation's output sha256 is the hash of
    the committed reproducer.nix on disk (the bytes finalize signs); the
    sampling sidecar records the same winning draw by index + raw-output sha,
    so the two records describe one winner (the raw and committed hashes match
    unless commit added a trailing newline the model omitted). The winner's
    real sampling temperature carried in the model block is the implicit
    sampled-vs-single-shot signal.

    Cost honesty: the sidecar bills the WHOLE sweep, not just the winning
    draw — every draw that reached the model (`billed_runs`) is summed via
    `extra_usages`, so `trace report` sees the true pass@K spend.

    Requires a pre-existing valid replay.json (the Patcher anchor). Returns
    the invocation dict, or None when replay.json is absent (a minimal /
    un-finalized bundle — the real sampler path guarantees it is present).
    """
    if not (bundle_dir / "replay.json").is_file():
        return None

    reproducer_run_meta: dict[str, Any] = {
        "prompt_sha256": winning_run.prompt_sha256,
        "user_content_sha256": winning_run.user_content_sha256,
        "raw_response_sha256": winning_run.raw_response_sha256,
        "model_id": winning_run.model_response.model_id,
        "sampling": winning_run.sampling,
        "kind": winning_run.kind,
        "is_proxy": winning_run.parsed.is_proxy,
        "refusal_rule": winning_run.parsed.refusal_rule,
        "refusal_reason": winning_run.parsed.refusal_reason,
        "adapter": winning_run.model_response.extras.get("adapter"),
    }

    patcher_family = _read_patcher_family_from_replay(bundle_dir)
    invocation = _build_reproducer_invocation(
        bundle_dir=bundle_dir,
        reproducer_run=reproducer_run_meta,
        outputs=outputs,
        started_at=started_at,
        ended_at=ended_at,
        patcher_family_recorded=patcher_family,
    )

    # Bill every draw's model spend, not only the winner's. The winner leads
    # (model_id / shas come from it); the other billed draws ride as extra
    # usages so the summed token totals reflect the full sweep.
    extra_usages = [
        r.model_response for r in billed_runs if r is not winning_run
    ]
    _write_role_invocation_sidecar(
        bundle_dir=bundle_dir,
        role="reproducer",
        cve_id=_read_bundle_cve_id(bundle_dir),
        invocation_id=invocation["invocation_id"],
        started_at=started_at,
        ended_at=ended_at,
        role_run_meta=reproducer_run_meta,
        model_response=winning_run.model_response,
        extra_usages=extra_usages,
    )
    _append_reproducer_replay_entry(bundle_dir=bundle_dir, invocation=invocation)
    return invocation


# ─── builder execution (deterministic; runner-backed) ───────────────────


def _execute_builder(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    verify: bool,
    build_runner_factory: object | None,
    nixpkgs_checkout: Path | None,
    builder_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Builder dispatcher.

    Builder is DETERMINISTIC (no LLM call) but its execution shape is
    subprocess-driven via the BuildRunner Protocol. Tests inject
    FakeBuildRunner via build_runner_factory; production passes a
    LocalNixBuildRunner factory once a Linux host is reachable.

    Per docs/BUILDER_V1.md sec.4: the replay invocation block carries
    `model.family='deterministic-no-model'` (mirroring the resolver
    invocation), `prompt: null`, and the new fields
    `patcher_invocation_id` + `reproducer_invocation_id` so an auditor
    can trace the build back to the model invocations it verified.
    """
    from agents.builder import BuilderRunResult, run_builder

    # The factory contract: callable(): -> BuildRunner. Defaults to
    # LocalNixBuildRunner when None — production path. Tests inject
    # a FakeBuildRunner factory.
    if build_runner_factory is None:
        from agents.builder import LocalNixBuildRunner
        build_runner = LocalNixBuildRunner()
    else:
        build_runner = build_runner_factory()  # type: ignore[misc]

    started_at = _utc_now_iso()
    run_builder_kwargs: dict[str, Any] = {
        "bundle_dir": bundle_dir,
        "build_runner": build_runner,
        "nixpkgs_checkout": nixpkgs_checkout,
        "apply_patch": nixpkgs_checkout is not None,
        "host_info": _default_builder_host_info(),
    }
    if builder_timeout_seconds is not None:
        run_builder_kwargs["timeout_seconds_per_build"] = builder_timeout_seconds
    result: BuilderRunResult = run_builder(**run_builder_kwargs)
    ended_at = _utc_now_iso()

    # Atomic-write build.json + (if needed) build.log sidecar.
    build_json_bytes = (
        json.dumps(result.build_json, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    _atomic_write_bytes(bundle_dir / "build.json", build_json_bytes)

    outputs: list[dict[str, Any]] = [{
        "path": "build.json",
        "sha256": sha256_hex(build_json_bytes),
        "bytes": len(build_json_bytes),
    }]

    # Persist any oversize logs as build.log. We concatenate the
    # full logs (truncation-only-on-stdout_stderr was already done
    # by run_builder); the sidecar carries the union, separated by
    # phase headers.
    full_logs = result.full_logs or {}
    if any(_log_oversize(text) for text in full_logs.values()):
        log_bytes = _assemble_build_log(full_logs).encode("utf-8")
        _atomic_write_bytes(bundle_dir / "build.log", log_bytes)
        outputs.append({
            "path": "build.log",
            "sha256": sha256_hex(log_bytes),
            "bytes": len(log_bytes),
        })

    input_verification: list[dict[str, Any]] = []
    for fname in ("patch.diff", "reproducer.nix", "package.nix"):
        p = bundle_dir / fname
        if p.is_file():
            input_verification.append({"path": fname, "verified": False})

    replay_invocation = _build_builder_invocation(
        bundle_dir=bundle_dir,
        outputs=outputs,
        started_at=started_at,
        ended_at=ended_at,
    )
    _append_builder_replay_entry(
        bundle_dir=bundle_dir, invocation=replay_invocation,
    )

    return {
        "role": "builder",
        "invocation_id": replay_invocation["invocation_id"],
        "dispatch_outcome": result.dispatch_outcome,
        "outputs": outputs,
        "input_verification": input_verification,
        "verified": verify,
        "build_json": result.build_json,
        "replay_invocation": replay_invocation,
    }


def _build_builder_invocation(
    *,
    bundle_dir: Path,
    outputs: list[dict[str, Any]],
    started_at: str,
    ended_at: str,
) -> dict[str, Any]:
    """Build a single replay-shape invocation record for a Builder run.

    Per docs/BUILDER_V1.md sec.4. Adds patcher_invocation_id +
    reproducer_invocation_id cross-references so an auditor can trace
    the build back to the model invocations it verified.
    """
    inputs: list[dict[str, Any]] = []
    for fname in ("patch.diff", "reproducer.nix", "package.nix"):
        p = bundle_dir / fname
        if p.is_file():
            inputs.append({"path": fname, "sha256": _file_sha256(p)})

    invocation = {
        "invocation_id": _gen_invocation_id(),
        "role": "builder",
        "started_at": started_at,
        "ended_at": ended_at,
        "model": {
            "family": "deterministic-no-model",
            "vendor": "internal",
            "model_id": "trace-builder-v0.1.0",
            "version": "0.1.0",
            "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
        },
        "prompt": None,
        "inputs": inputs,
        "outputs": [{"path": o["path"], "sha256": o["sha256"]} for o in outputs],
        "patcher_invocation_id":
            _read_role_latest_invocation_id(bundle_dir, "patcher"),
        "reproducer_invocation_id":
            _read_role_latest_invocation_id(bundle_dir, "reproducer"),
        "rng_seed": None,
        "validators_passed": ["build-json-shape-valid"],
        "network_policy_applied": "substituter-only",
    }
    return invocation


def _read_role_latest_invocation_id(
    bundle_dir: Path, role: str,
) -> str | None:
    """Most-recent invocation_id for a given role in replay.json."""
    rj = bundle_dir / "replay.json"
    if not rj.is_file():
        return None
    try:
        replay = json.loads(rj.read_text())
    except json.JSONDecodeError:
        return None
    for r in replay.get("roles", []):
        if r.get("role") != role:
            continue
        invs = r.get("invocations", [])
        if not invs:
            continue
        return invs[-1].get("invocation_id")
    return None


def _append_builder_replay_entry(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
) -> None:
    """Append a Builder invocation into replay.json's roles[]."""
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        raise ExecutionError(
            f"replay.json missing in {bundle_dir}; builder requires a "
            f"pre-existing replay.json (the patcher + reproducer "
            f"invocations are its anchors)."
        )
    replay = json.loads(replay_path.read_text())
    roles = replay.setdefault("roles", [])
    role_entry = None
    for r in roles:
        if r.get("role") == "builder":
            role_entry = r
            break
    if role_entry is None:
        role_entry = {"role": "builder", "invocations": []}
        roles.append(role_entry)
    role_entry["invocations"].append(invocation)
    body = json.dumps(replay, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_bytes(replay_path, body.encode("utf-8"))


def _default_builder_host_info() -> dict[str, str]:
    import platform
    import shutil
    import subprocess as _sp
    system = platform.machine() + "-" + (
        "linux" if platform.system().lower() == "linux"
        else platform.system().lower().replace("darwin", "darwin")
    )
    nix_version = "unknown"
    if shutil.which("nix-build"):
        try:
            out = _sp.run(
                ["nix-build", "--version"],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if out.stdout:
                nix_version = out.stdout.strip().splitlines()[0]
        except (OSError, _sp.SubprocessError):
            pass
    return {
        "system": system,
        "nix_version": nix_version,
        "tool_version": "trace-cli/0.0.0",
    }


def _log_oversize(text: str) -> bool:
    from agents.builder.protocol import INLINE_STDOUT_STDERR_CAP_BYTES
    return len(text.encode("utf-8")) > INLINE_STDOUT_STDERR_CAP_BYTES


def _assemble_build_log(full_logs: dict[str, str]) -> str:
    """Concatenate phase logs into a single build.log sidecar body."""
    parts: list[str] = []
    for phase in ("patched_build", "unpatched", "patched"):
        body = full_logs.get(phase, "")
        parts.append(f"=== {phase} ===\n{body}\n")
    return "".join(parts)
