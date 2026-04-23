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

NON_DETERMINISTIC_ROLES: frozenset[str] = frozenset({
    "patcher",
    "reviewer",
    "reproducer",
})


class ExecutionError(Exception):
    """Raised for structural problems (missing input, unsupported role, etc.)."""


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
) -> dict[str, Any]:
    """Execute one deterministic stub role for one invocation record.

    Returns:
        {
          "role": str,
          "invocation_id": str,
          "outputs": [{"path": str, "declared_sha256": str, "computed_sha256": str, "content": Any}],
          "input_verification": [{"path": str, "verified": bool}],
          "verified": bool,
        }
    """
    if role in NON_DETERMINISTIC_ROLES:
        raise ExecutionError(
            f"role {role!r} is non-deterministic (Patcher/Reviewer/Reproducer) "
            f"and cannot be --execute'd in v0 replay. No model calls allowed until "
            f"eval corpus is frozen (see docs/DECISIONS.md 2026-04-23)."
        )
    if role not in DETERMINISTIC_ROLES:
        raise ExecutionError(
            f"role {role!r} is not supported for --execute in v0 "
            f"(supported: {sorted(DETERMINISTIC_ROLES)})"
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
