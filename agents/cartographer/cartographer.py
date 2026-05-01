"""Cartographer — v0 stub.

Deterministic. Given a `finding.json`-shaped dict and a CartographerGraph,
emits an `impact.json`-shaped dict and a `maintainers.json`-shaped dict.

No policy decisions. Cartographer reports facts (reverse-closure counts,
maintainer sets, critical-downstream flags) and the single derived boolean
`exceeds_threshold`. What those facts mean for bundle.kind is Steward's job
(rule §6 gate 4).

No network, no I/O outside what the caller provides.
"""

from __future__ import annotations

from typing import Any

from agents.cartographer.graph import CartographerGraph


IMPACT_SCHEMA_VERSION = "1.0.0"
MAINTAINERS_SCHEMA_VERSION = "1.0.0"

DEFAULT_BLAST_RADIUS_THRESHOLD = 500
DEFAULT_THRESHOLD_POLICY = "v0-default"
DEFAULT_SAMPLE_SIZE = 10


def analyze(
    finding: dict[str, Any],
    graph: CartographerGraph,
    nixpkgs_rev: str,
    blast_radius_threshold: int = DEFAULT_BLAST_RADIUS_THRESHOLD,
    threshold_policy: str = DEFAULT_THRESHOLD_POLICY,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    analysis_status: str = "complete",
    analysis_reason: str | None = None,
) -> dict[str, Any]:
    """Return {"impact": impact_dict, "maintainers": maintainers_dict}."""
    cve_id: str = finding["cve_id"]
    affected_entries = finding["affected"]
    affected_attrs = [e["attr_path"] for e in affected_entries]

    per_attr: list[dict[str, Any]] = []
    union_closure: set[str] = set()
    union_critical: set[str] = set()

    for entry in affected_entries:
        attr = entry["attr_path"]
        drv = entry["drv_path"]
        closure = list(graph.reverse_closure(attr))
        crit = list(graph.critical_downstreams(attr))
        count = len(closure)
        per_attr.append({
            "attr_path": attr,
            "drv_path": drv,
            "reverse_closure_count": count,
            "reverse_closure_bucket": _bucket(count),
            "reverse_closure_sample": closure[:sample_size],
            "critical_downstreams": crit,
            "exceeds_threshold": count > blast_radius_threshold,
        })
        union_closure.update(closure)
        union_critical.update(crit)

    total_count = len(union_closure)
    impact: dict[str, Any] = {
        "schema_version": IMPACT_SCHEMA_VERSION,
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "blast_radius_threshold": blast_radius_threshold,
        "threshold_policy": threshold_policy,
        "affected_attr_paths": list(dict.fromkeys(affected_attrs)),
        "reverse_closure_count": total_count,
        "reverse_closure_bucket": _bucket(total_count),
        "reverse_closure_sample": sorted(union_closure)[:sample_size],
        "critical_downstreams": sorted(union_critical),
        "exceeds_threshold": total_count > blast_radius_threshold,
        "per_attr": per_attr,
        "replay_critical": True,
        "analysis_status": analysis_status,
    }
    if analysis_reason is not None:
        impact["analysis_reason"] = analysis_reason

    maint_section: dict[str, dict[str, Any]] = {}
    for attr in impact["affected_attr_paths"]:
        maints = list(graph.maintainers(attr))
        maint_section[attr] = {
            "maintainers": [_maintainer_to_dict(m) for m in maints]
        }

    maintainers: dict[str, Any] = {
        "schema_version": MAINTAINERS_SCHEMA_VERSION,
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "attr_paths": maint_section,
        "replay_critical": True,
    }

    return {"impact": impact, "maintainers": maintainers}


def _bucket(count: int) -> str:
    if count < 50:
        return "<50"
    if count <= 500:
        return "50-500"
    if count <= 5000:
        return "500-5000"
    return ">5000"


def _maintainer_to_dict(m: Any) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if m.github is not None:
        d["github"] = m.github
    if m.email is not None:
        d["email"] = m.email
    if m.name is not None:
        d["name"] = m.name
    return d
