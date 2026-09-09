"""Build the `clean-v9-supplemented` authoring training variant.

Codex <redacted-session-id> (2026-07-14): the v10 clean re-baseline preserved focused-site
localization but lost full-window distractor-resistance, because the 21 stratified
real-diff supplements were excluded (they are authoring-only pairs with no build.json,
so the behavioral-validation gate drops them). This variant grafts them back with an
explicit `grounded-unvalidated` provenance tier to test whether distractor-resistance
returns without reintroducing bad labels.

Base = the fully-behaviorally-validated export (exports/authoring-lora/authoring.{train,dev}.jsonl).
Graft = the 21 supplements, each re-checked through the SAME integrity gates the exporter
applies (leak-scrub, whole-label grounding, self-leak, upstream-grounded), formatted
identically to a validated row, added to TRAIN. `grounded-unvalidated` rows are EXCLUDED
from the behaviorally-validated corpus counts; this is an experiment-only variant.

Run: nix develop .#lora --command python3 lora/build_clean_v9_supplemented.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.trace_cli.export import (  # noqa: E402
    _AUTHORING_SYSTEM,
    _redact,
    _fence_lang_for,
    _scrub_summary,
    _fix_symbols,
    _REMEDIATION_RE,
    _mentions,
    _label_fully_grounded,
    _label_self_leaked,
)

REPO = Path(__file__).resolve().parents[1]
BASE = REPO / "exports" / "authoring-lora"
OUT = REPO / "exports" / "authoring-lora-supplemented"
TRACES = REPO / "traces" / "example"

# The 21 v9 stratified real-diff supplements (v1.3 job script), in order.
SUPPLEMENTS = [
    "CVE-2019-12900",
    "CVE-2019-3863",
    "CVE-2025-69693",
    "CVE-2017-12652",
    "CVE-2020-15503",
    "CVE-2025-5917",
    "CVE-2015-8784",
    "CVE-2017-12898",
    "CVE-2017-13024",
    "CVE-2018-13785",
    "CVE-2019-18218",
    "CVE-2021-23017",
    "CVE-2021-28677",
    "CVE-2021-3520",
    "CVE-2021-3575",
    "CVE-2023-3603",
    "CVE-2024-25629",
    "CVE-2024-37407",
    "CVE-2024-49766",
    "CVE-2025-57052",
    "CVE-2026-7135",
]
CANARIES = {"CVE-2022-37434", "CVE-2026-42250", "CVE-2024-47081", "CVE-2026-48526"}


def _supplement_dir(cve: str) -> Path | None:
    for d in sorted(TRACES.glob(f"{cve}*")):
        if (d / "authoring-example.json").is_file():
            return d
    return None


def _build_row(cve: str, cache: dict) -> dict | None:
    """Format a supplement exactly like the exporter's validated row, after re-running
    every integrity gate. Returns the {messages} training record or None if it fails a
    gate (defensive — the caller already pre-screened, this is the authoritative check)."""
    vuln_raw = cache.get("vuln_raw") or ""
    pre = cache.get("pre_fix_source") or ""
    diff = cache.get("fix_diff") or ""
    if not (vuln_raw and pre and diff):
        return None
    included = cache.get("included_source_files") or (
        [cache["file"]] if cache.get("file") else None
    )
    vuln = _scrub_summary(vuln_raw, diff)
    fix_syms = _fix_symbols(diff)
    if (
        not vuln
        or _REMEDIATION_RE.search(vuln)
        or any(_mentions(vuln, s) for s in fix_syms)
    ):
        return None
    if not _label_fully_grounded(diff, pre, included):
        return None
    if _label_self_leaked(diff, pre):
        return None
    inc = included or [cache.get("file", cve)]
    src_header = ", ".join(inc)
    fence = _fence_lang_for(inc)
    user = (
        f"# CVE\n{cache.get('cve_id', cve)}: {vuln}\n\n"
        f"# Vulnerable source ({src_header})\n```{fence}\n{pre}\n```"
    )
    return {
        "messages": [
            {"role": "system", "content": _redact(_AUTHORING_SYSTEM)},
            {"role": "user", "content": _redact(user)},
            {"role": "assistant", "content": _redact(diff)},
        ],
    }


def main() -> int:
    base_train = [
        json.loads(l)
        for l in (BASE / "authoring.train.jsonl").read_text().splitlines()
        if l.strip()
    ]
    base_dev = [
        json.loads(l)
        for l in (BASE / "authoring.dev.jsonl").read_text().splitlines()
        if l.strip()
    ]

    grafted, dropped = [], []
    for cve in SUPPLEMENTS:
        d = _supplement_dir(cve)
        if d is None:
            dropped.append((cve, "no-cache"))
            continue
        cache = json.loads((d / "authoring-example.json").read_text())
        # upstream-grounded, not nixpkgs packaging
        uref = (
            json.loads((d / "upstream-ref.json").read_text())
            if (d / "upstream-ref.json").is_file()
            else {}
        )
        if "nixos/nixpkgs" in json.dumps(uref).lower():
            dropped.append((cve, "nixpkgs-packaging"))
            continue
        row = _build_row(cve, cache)
        if row is None:
            dropped.append((cve, "failed-integrity-gate"))
            continue
        grafted.append((cve, row))

    # canary exclusion guard
    leaked = [cve for cve, _ in grafted if cve in CANARIES]
    if leaked:
        raise SystemExit(f"ABORT: canary CVE grafted as supplement: {leaked}")

    train = base_train + [r for _, r in grafted]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "authoring.train.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in train)
    )
    (OUT / "authoring.dev.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in base_dev)
    )

    def _est_tokens(r: dict) -> int:
        return sum(len(m["content"]) for m in r["messages"]) // 4

    over = [i for i, r in enumerate(train) if _est_tokens(r) > 16384]
    manifest = {
        "variant": "clean-v9-supplemented",
        "base_validated_train": len(base_train),
        "grafted_grounded_unvalidated": len(grafted),
        "supplemented_train_total": len(train),
        "dev": len(base_dev),
        "supplements_grafted": [c for c, _ in grafted],
        "supplements_dropped": dropped,
        "max_est_tokens": max(_est_tokens(r) for r in train),
        "over_length": len(over),
        "note": (
            "grounded-unvalidated supplements pass grounding/self-leak/dedup/scrub and are "
            "upstream-source-commit grounded, but lack behavioral validation; EXCLUDED from "
            "behaviorally-validated corpus counts. Experiment-only variant (codex <redacted-session-id>)."
        ),
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
