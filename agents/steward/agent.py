"""Steward routing agent.

Thin runtime over policy/steward_route.rego. Reads a Scout inbox entry
(finding.json, upstream-ref.json, optional mapping-failure.json),
asks OPA which routing state applies, and writes steward-decision.json
back into the entry.

The Steward agent does NOT encode policy. Every classification rule
lives in the rego file; this module's job is to build the OPA input
doc, run `opa eval`, and persist the structured result.

Two distinct policies coexist:

  * trace.steward (steward.rego)         pre-merge gate, runs against a
                                          fully-assembled bundle. Existing.
  * trace.steward.route (steward_route.rego)
                                          Scout-level routing classifier
                                          built in this slice.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_FILE = _REPO_ROOT / "policy" / "steward_route.rego"
_OPA_QUERY = "data.trace.steward.route"


class OpaUnavailable(RuntimeError):
    """opa binary is not on PATH. Steward cannot decide without it."""


def route_inbox_entry(entry: Path) -> dict[str, Any]:
    """Classify an inbox entry into a routing state and persist the
    decision. Returns the decision dict."""
    finding = _load(entry / "finding.json")
    upstream_ref = _load(entry / "upstream-ref.json")
    mapping_failure = _load(entry / "mapping-failure.json")

    opa_input: dict[str, Any] = {}
    if finding is not None:
        opa_input["finding"] = finding
    if upstream_ref is not None:
        opa_input["upstream_ref"] = upstream_ref
    if mapping_failure is not None:
        opa_input["mapping_failure"] = mapping_failure

    raw = _run_opa(opa_input)
    state = raw.get("state", "reject")
    reason_codes = sorted(raw.get("reason_codes", []))

    cve_id = _resolve_cve_id(finding, upstream_ref, mapping_failure, entry)

    decision: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "decided_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "state": state,
        "reason_codes": reason_codes,
        "evaluator": f"opa-rego/{_OPA_QUERY}",
        "policy_sha256": _policy_sha256(),
        "inputs_summary": _summarize(finding, upstream_ref, mapping_failure),
    }

    _atomic_write_json(entry / "steward-decision.json", decision)
    return decision


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def _resolve_cve_id(
    finding: dict[str, Any] | None,
    upstream_ref: dict[str, Any] | None,
    mapping_failure: dict[str, Any] | None,
    entry: Path,
) -> str:
    for src in (finding, upstream_ref, mapping_failure):
        if isinstance(src, dict) and isinstance(src.get("cve_id"), str):
            return src["cve_id"]
    return entry.name


def _summarize(
    finding: dict[str, Any] | None,
    upstream_ref: dict[str, Any] | None,
    mapping_failure: dict[str, Any] | None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "finding_status": "finding" if finding else (
            "mapping-failure" if mapping_failure else "absent"
        ),
        "resolver_verdict": None,
        "resolver_trigger": None,
        "confidence_high_only": None,
    }
    if upstream_ref:
        eligibility = upstream_ref.get("eligibility") or {}
        summary["resolver_verdict"] = eligibility.get("verdict")
        summary["resolver_trigger"] = eligibility.get("human_review_trigger")
    if finding:
        affected = finding.get("affected") or []
        if affected:
            summary["confidence_high_only"] = all(
                a.get("confidence") == "high" for a in affected
            )
    return summary


def _run_opa(opa_input: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("opa") is None:
        raise OpaUnavailable(
            "opa binary not found on PATH; install via "
            "`nix profile install nixpkgs#open-policy-agent` or use trace's dev shell"
        )
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format=json",
            "--data", str(_POLICY_FILE),
            "--stdin-input",
            _OPA_QUERY,
        ],
        input=json.dumps(opa_input),
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(proc.stdout)
    return result["result"][0]["expressions"][0]["value"]


def _policy_sha256() -> str:
    return hashlib.sha256(_POLICY_FILE.read_bytes()).hexdigest()


def _atomic_write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
