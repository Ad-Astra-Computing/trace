"""Helper used by .github/workflows/real-prefetch-smoke.yml.

Scores the latest Patcher invocation in a bundle's replay.json against
the six locked scorers, and writes scoring-report.json to the bundle
dir. Kept as a standalone script so the workflow YAML stays small and
the scoring step is auditable on its own.

Usage:
    python tests/fixtures/real-ci/score_invocation.py <bundle_dir>

Exits non-zero if the bundle has no patcher invocation or the scorer
runner refuses (advisory-only / ineligible-* dispatch guard).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure trace's package root is on sys.path even when this script is
# invoked by absolute path (the CI workflow does this; pytest configures
# rootdir for unit tests but `python <path>` does not).
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agents.scorers import ScoringRefused, run_scorers  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} <bundle_dir>", file=sys.stderr)
        return 2

    bundle_dir = Path(argv[0])
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        print(f"error: {replay_path} missing", file=sys.stderr)
        return 1

    replay = json.loads(replay_path.read_text())
    patcher_invs = [
        i for r in replay.get("roles", []) if r.get("role") == "patcher"
        for i in r.get("invocations", [])
    ]
    if not patcher_invs:
        print(f"error: no patcher invocation in {replay_path}", file=sys.stderr)
        return 1
    invocation = patcher_invs[-1]

    try:
        report = run_scorers(bundle_dir=bundle_dir, invocation=invocation)
    except ScoringRefused as exc:
        print(f"scoring refused: {exc}", file=sys.stderr)
        return 1

    out_path = bundle_dir / "scoring-report.json"
    out_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    print(f"wrote {out_path}")
    print(f"  patcher_kind:                {report.patcher_kind}")
    print(f"  composite_merge_ready_rate:  {report.composite_merge_ready_rate}")
    print(f"  scorers_in_denominator:      {report.scorers_in_denominator}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
