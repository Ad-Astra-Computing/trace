"""Bridge a Scout inbox entry to Patcher's run_patcher inputs.

Reads finding.json + upstream-ref.json + steward-decision.json from
inbox/<CVE>/, calls Cartographer.analyze for impact + maintainers,
and resolves package_source via path_resolver. Refuses entries
whose Steward state is not auto-merge-eligible.

Slice 2 of the Patcher pipeline. Slice 4 builds the CLI on top.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.cartographer.cartographer import analyze as cartographer_analyze
from agents.cartographer.graph import CartographerGraph
from agents.patcher.path_resolver import (
    PackageSourceNotFound,
    resolve_package_source,
)


_AUTO_MERGE_STATE = "auto-merge-eligible"


class InboxBundleNotReady(RuntimeError):
    """Required inbox artefact missing or package source unresolvable."""


class BridgeRefused(RuntimeError):
    """Steward did not classify this entry as auto-merge-eligible."""


@dataclass(frozen=True)
class AssembledInputs:
    inputs: dict[str, Any]
    steward_state: str


def assemble_inputs_from_inbox(
    entry: Path,
    *,
    nixpkgs_root: Path,
    graph: CartographerGraph,
    nixpkgs_rev: str,
    use_nix_eval: bool = False,
    write_to_inbox: bool = False,
) -> AssembledInputs:
    finding = _load_required(entry, "finding.json")
    upstream_ref = _load_required(entry, "upstream-ref.json")
    decision = _load_required(entry, "steward-decision.json")

    state = decision.get("state")
    if state != _AUTO_MERGE_STATE:
        raise BridgeRefused(
            f"steward state for {entry.name} is {state!r}, not "
            f"{_AUTO_MERGE_STATE!r}; refusing to assemble Patcher inputs"
        )

    cart = cartographer_analyze(
        finding=finding,
        graph=graph,
        nixpkgs_rev=nixpkgs_rev,
    )
    impact = cart["impact"]
    maintainers = cart["maintainers"]

    affected = finding.get("affected") or []
    if not affected:
        raise InboxBundleNotReady(
            f"finding has no `affected` entries; cannot resolve package source"
        )
    attr_path = affected[0]["attr_path"]
    try:
        pkg_source = resolve_package_source(
            attr_path,
            nixpkgs_root=nixpkgs_root,
            use_nix_eval=use_nix_eval,
        )
    except PackageSourceNotFound as e:
        raise InboxBundleNotReady(
            f"could not resolve package source for {attr_path!r}: {e}"
        ) from e

    inputs: dict[str, Any] = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": pkg_source.content,
        "package_source_path": pkg_source.relative,
    }

    if write_to_inbox:
        _atomic_write_json(entry / "impact.json", impact)
        _atomic_write_json(entry / "maintainers.json", maintainers)

    return AssembledInputs(inputs=inputs, steward_state=state)


def _load_required(entry: Path, name: str) -> dict[str, Any]:
    path = entry / name
    if not path.is_file():
        raise InboxBundleNotReady(
            f"required inbox artefact missing: {name} (in {entry})"
        )
    return json.loads(path.read_text(encoding="utf-8"))


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
