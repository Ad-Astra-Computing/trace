"""nixpkgs graph snapshot builder.

Calls `nix-env -qaP --json` against a nixpkgs source and converts the
result into a list of `GraphMatch` records suitable for
`CannedGraphLookup`. Closes the relevance-filter gap that previously
forced the cron to consume a hand-written single-attr fixture.

What v0 captures:
  * attr_path
  * pname (lowercased to keep both sides of the dict lookup aligned)
  * version
  * drv_path placeholder ("attr:<attr_path>"); `nix-env -qaP` does
    not emit drvPath
  * cpes / purls left empty: relevance matching goes through pname
    via CVE normalizers' pname_hints

What v0 explicitly does NOT do:
  * CPE indexing (vendor disambiguation is its own ranking problem)
  * Reverse-closure / dependency graph (Cartographer concern)
  * drvPath resolution (slow; future slice)

The subprocess runner is injectable so tests stay offline. A live
smoke is gated on TRACE_REAL_NIX_ENV=1.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable

from agents.scout.graph_lookup import GraphMatch


_DEFAULT_NIXPKGS = "<nixpkgs>"
_DEFAULT_TIMEOUT_S = 1800  # 30 minutes; full nixpkgs eval can take a while


RunnerFn = Callable[..., subprocess.CompletedProcess[bytes]]


class SnapshotBuildError(Exception):
    """The nix-env invocation or its output failed to produce a usable snapshot."""


def build_snapshot(
    *,
    nixpkgs: str = _DEFAULT_NIXPKGS,
    runner: RunnerFn | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    with_drv_paths: bool = True,
) -> list[GraphMatch]:
    cmd = ["nix-env", "-qaP", "--json", "-f", nixpkgs]
    if with_drv_paths:
        cmd.append("--drv-path")
    runner_fn = runner or _default_runner

    try:
        proc = runner_fn(cmd, timeout=timeout_s)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise SnapshotBuildError(f"nix-env invocation failed: {e}") from e

    if proc.returncode != 0:
        raise SnapshotBuildError(
            f"nix-env failed (returncode={proc.returncode}): "
            f"{proc.stderr.decode(errors='replace').strip()[:500]}"
        )

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise SnapshotBuildError(f"nix-env stdout is not valid JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise SnapshotBuildError(
            f"nix-env top-level shape must be an object keyed by attr path; got {type(parsed).__name__}"
        )

    records: list[GraphMatch] = []
    for attr_path, info in parsed.items():
        if not isinstance(info, dict):
            continue
        pname_raw = info.get("pname")
        if not isinstance(pname_raw, str) or not pname_raw:
            continue
        version = info.get("version")
        if not isinstance(version, str):
            version = ""
        drv_path_raw = info.get("drvPath")
        drv_path = (
            drv_path_raw
            if isinstance(drv_path_raw, str) and drv_path_raw
            else f"attr:{attr_path}"
        )
        records.append(
            GraphMatch(
                attr_path=attr_path,
                drv_path=drv_path,
                pname=pname_raw.lower(),
                version=version,
            )
        )
    return records


def snapshot_to_json(records: list[GraphMatch]) -> str:
    """Emit the JSON array shape consumed by agents.scout.poll_cli."""
    payload = [
        {
            "attr_path": r.attr_path,
            "drv_path": r.drv_path,
            "pname": r.pname,
            "version": r.version,
            "cpes": list(r.cpes),
            "purls": list(r.purls),
            "src_url": r.src_url,
            "src_hash": r.src_hash,
        }
        for r in records
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def snapshot_from_json(text: str) -> list[GraphMatch]:
    raw = json.loads(text)
    if not isinstance(raw, list):
        raise ValueError("snapshot must be a JSON array")
    out: list[GraphMatch] = []
    for entry in raw:
        out.append(
            GraphMatch(
                attr_path=entry["attr_path"],
                drv_path=entry["drv_path"],
                pname=entry["pname"],
                version=entry["version"],
                cpes=tuple(entry.get("cpes") or ()),
                purls=tuple(entry.get("purls") or ()),
                src_url=entry.get("src_url"),
                src_hash=entry.get("src_hash"),
            )
        )
    return out


def _default_runner(
    cmd: list[str], *, timeout: int
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
