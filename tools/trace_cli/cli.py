"""trace CLI skeleton.

v0 scope (§6.0 build-order exception; see docs/DECISIONS.md 2026-04-23):
  * `trace replay <bundle-id>`  — load the bundle, validate its replay.json,
                                  print the recorded replay plan.
  * `--role <role> --model <model-id>` — override exactly one role. Validated.
  * `--routing-config <path>`   — override multiple roles via a JSON file.
                                  Mutually exclusive with --role/--model.
  * bare `--model`              — rejected (ambiguous).
  * bare `--role`               — rejected (incomplete).

Hard constraints:
  * No network. The CLI never opens a socket.
  * No role execution. Every role emits `status: stub` in the plan.
  * Frozen inputs. The plan reports exactly what replay.json recorded; the
    only permitted mutations are override substitutions on `model.model_id`
    (and `model.family` when supplied in a routing config).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


ROLE_NAMES = (
    "scout",
    "cartographer",
    "upstream-ref-resolver",
    "patcher",
    "reproducer",
    "builder",
    "reviewer",
    "steward",
)


EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_INVALID = 4
EXIT_HASH_MISMATCH = 5


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="trace",
        description="trace — agent-owned nixpkgs fork CLI (v0 skeleton).",
    )
    subs = parser.add_subparsers(dest="cmd", required=True)

    rv = subs.add_parser("review", help="panel review rubric tooling")
    rv_subs = rv.add_subparsers(dest="review_cmd", required=True)
    rv_sum = rv_subs.add_parser(
        "summarize",
        help="aggregate review rubric JSON files in a directory",
    )
    rv_sum.add_argument(
        "path",
        type=Path,
        help="directory containing review rubric JSON files",
    )
    rv_sum.add_argument(
        "--bundle",
        help="filter reviews to a single bundle_id",
    )
    rv_sum.add_argument(
        "--include-examples",
        action="store_true",
        help="include entries with is_example=true (excluded by default)",
    )
    rv_sum.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
    )

    r = subs.add_parser("replay", help="replay a recorded bundle (stub runner)")
    r.add_argument(
        "bundle_id",
        help="bundle_id (16-hex), CVE id, or fixture directory name/path",
    )
    r.add_argument(
        "--role",
        choices=list(ROLE_NAMES),
        help="override a single role (requires --model)",
    )
    r.add_argument(
        "--model",
        help="model id override (requires --role)",
    )
    r.add_argument(
        "--routing-config",
        type=Path,
        help="JSON file with { role: {model_id, family?} } (mutually exclusive with --role/--model)",
    )
    r.add_argument(
        "--traces-root",
        type=Path,
        default=Path(os.environ.get("TRACE_TRACES_ROOT", "traces")),
        help="root directory to search for bundles (default: ./traces or $TRACE_TRACES_ROOT)",
    )
    r.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="output format (default: human)",
    )
    r.add_argument(
        "--execute",
        action="store_true",
        help=(
            "actually run the stub role against frozen inputs (deterministic roles "
            "only: scout, cartographer, upstream-ref-resolver). Requires --role."
        ),
    )
    r.add_argument(
        "--no-verify",
        action="store_true",
        help="skip input+output sha256 verification during --execute",
    )

    args = parser.parse_args(argv)
    if args.cmd == "replay":
        return _cmd_replay(args)
    if args.cmd == "review":
        if args.review_cmd == "summarize":
            return _cmd_review_summarize(args)
        return EXIT_USAGE
    return EXIT_USAGE


def _cmd_review_summarize(args: argparse.Namespace) -> int:
    from tools.trace_cli.review import emit_summary, load_reviews, summarize

    try:
        reviews = load_reviews(
            args.path,
            include_examples=args.include_examples,
            bundle_filter=args.bundle,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_NOT_FOUND
    print(emit_summary(summarize(reviews), args.format))
    return EXIT_OK


def _cmd_replay(args: argparse.Namespace) -> int:
    err = _validate_override_args(args)
    if err is not None:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_USAGE

    bundle_dir = _locate_bundle(args.bundle_id, args.traces_root)
    if bundle_dir is None:
        print(
            f"error: bundle {args.bundle_id!r} not found under {args.traces_root}",
            file=sys.stderr,
        )
        return EXIT_NOT_FOUND

    try:
        bundle = json.loads((bundle_dir / "bundle.json").read_text())
        replay = json.loads((bundle_dir / "replay.json").read_text())
    except FileNotFoundError as exc:
        print(f"error: bundle directory missing required file: {exc}", file=sys.stderr)
        return EXIT_INVALID

    overrides, err = _build_overrides(args)
    if err is not None:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_USAGE

    if args.execute:
        return _do_execute(args, bundle, replay, bundle_dir)

    plan = build_replay_plan(bundle, replay, overrides, bundle_dir=bundle_dir)
    _emit_plan(plan, args.format)
    return EXIT_OK


def _do_execute(
    args: argparse.Namespace,
    bundle: dict[str, Any],
    replay: dict[str, Any],
    bundle_dir: Path,
) -> int:
    from tools.trace_cli.execute import ExecutionError, HashMismatch, execute

    role_entry = None
    for entry in replay.get("roles", []):
        if entry.get("role") == args.role:
            role_entry = entry
            break
    if role_entry is None:
        print(
            f"error: no invocations for role {args.role!r} in replay.json",
            file=sys.stderr,
        )
        return EXIT_NOT_FOUND

    results: list[dict[str, Any]] = []
    for invocation in role_entry["invocations"]:
        try:
            result = execute(
                role=args.role,
                bundle_dir=bundle_dir,
                invocation=invocation,
                verify=not args.no_verify,
            )
        except HashMismatch as exc:
            print(f"hash-mismatch: {exc}", file=sys.stderr)
            return EXIT_HASH_MISMATCH
        except ExecutionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID
        results.append(result)

    _emit_execute_results(
        {
            "bundle_id": bundle.get("bundle_id"),
            "cve_id": bundle.get("cve_id"),
            "role": args.role,
            "verified": not args.no_verify,
            "executor": "deterministic-stub",
            "results": [
                {
                    "invocation_id": r["invocation_id"],
                    "outputs": [
                        {
                            "path": o["path"],
                            "declared_sha256": o["declared_sha256"],
                            "computed_sha256": o["computed_sha256"],
                            "match": o["declared_sha256"] == o["computed_sha256"],
                        }
                        for o in r["outputs"]
                    ],
                    "input_verification": r["input_verification"],
                }
                for r in results
            ],
        },
        args.format,
    )
    return EXIT_OK


def _emit_execute_results(report: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report, indent=2))
        return
    print(f"bundle_id: {report['bundle_id']}")
    print(f"cve_id:    {report['cve_id']}")
    print(f"role:      {report['role']}")
    print(f"verified:  {report['verified']}")
    print(f"executor:  {report['executor']}")
    for r in report["results"]:
        print(f"\ninvocation_id: {r['invocation_id']}")
        for o in r["outputs"]:
            mark = "✓" if o["match"] else "✗"
            print(f"  {mark} {o['path']}  computed={o['computed_sha256'][:12]}… declared={o['declared_sha256'][:12]}…")


def _validate_override_args(args: argparse.Namespace) -> str | None:
    if args.routing_config and (args.role or args.model):
        return "--routing-config is mutually exclusive with --role/--model"
    if args.execute:
        # In execute mode, --role is required; --model is not. Override semantics
        # (model substitution) are plan-only in v0.
        if not args.role:
            return "--execute requires --role"
        if args.routing_config:
            return "--execute is not compatible with --routing-config in v0"
        return None
    if args.role and not args.model:
        return "--role requires --model"
    if args.model and not args.role:
        return "--model requires --role (or use --routing-config for multi-role)"
    return None


def _locate_bundle(identifier: str, traces_root: Path) -> Path | None:
    # Direct path: caller passed a fixture directory.
    as_path = Path(identifier)
    if as_path.is_dir() and (as_path / "bundle.json").is_file():
        return as_path

    if not traces_root.is_dir():
        return None

    # Walk traces_root for a bundle.json matching either bundle_id or cve_id
    # or whose enclosing directory name matches `identifier`.
    for candidate in sorted(traces_root.rglob("bundle.json")):
        bundle_dir = candidate.parent
        if bundle_dir.name == identifier:
            return bundle_dir
        try:
            meta = json.loads(candidate.read_text())
        except json.JSONDecodeError:
            continue
        if meta.get("bundle_id") == identifier or meta.get("cve_id") == identifier:
            return bundle_dir
    return None


def _build_overrides(args: argparse.Namespace) -> tuple[dict[str, dict[str, str]], str | None]:
    if args.role and args.model:
        return {args.role: {"model_id": args.model}}, None
    if args.routing_config:
        try:
            raw = json.loads(args.routing_config.read_text())
        except FileNotFoundError:
            return {}, f"routing-config file not found: {args.routing_config}"
        except json.JSONDecodeError as exc:
            return {}, f"routing-config is not valid JSON: {exc}"
        err = _validate_routing_config(raw)
        if err:
            return {}, err
        return raw, None
    return {}, None


def _validate_routing_config(rc: Any) -> str | None:
    if not isinstance(rc, dict):
        return "routing-config must be a JSON object mapping role -> { model_id, family? }"
    if not rc:
        return "routing-config is empty; supply at least one role override"
    allowed_role_keys = set(ROLE_NAMES)
    for role, spec in rc.items():
        if role not in allowed_role_keys:
            return f"routing-config: {role!r} is not a known role (expected one of {sorted(allowed_role_keys)})"
        if not isinstance(spec, dict):
            return f"routing-config[{role}]: value must be an object"
        if "model_id" not in spec or not isinstance(spec["model_id"], str) or not spec["model_id"]:
            return f"routing-config[{role}]: missing or empty model_id"
        extra = set(spec.keys()) - {"model_id", "family"}
        if extra:
            return f"routing-config[{role}]: unknown keys {sorted(extra)}"
        if "family" in spec and not isinstance(spec["family"], str):
            return f"routing-config[{role}].family must be a string"
    return None


# ─── plan construction + stub execution ──────────────────────────────────────


def build_replay_plan(
    bundle: dict[str, Any],
    replay: dict[str, Any],
    overrides: dict[str, dict[str, str]],
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    """Build the replay plan from frozen inputs, applying overrides per role.

    The plan mirrors replay.json.roles[].invocations[] but records:
      - original model (from replay.json)
      - override model (if any applies to this invocation's role)
      - runner status: always 'stub' in v0
    """

    invocations: list[dict[str, Any]] = []
    for role_entry in replay.get("roles", []):
        role = role_entry.get("role")
        override = overrides.get(role)
        for inv in role_entry.get("invocations", []):
            entry: dict[str, Any] = {
                "role": role,
                "invocation_id": inv["invocation_id"],
                "prompt_sha256": inv["prompt"]["sha256"],
                "input_sha256s": [r["sha256"] for r in inv["inputs"]],
                "output_sha256s": [r["sha256"] for r in inv["outputs"]],
                "original_model": {
                    "family": inv["model"]["family"],
                    "model_id": inv["model"]["model_id"],
                    "version": inv["model"]["version"],
                },
                "network_policy_applied": inv.get("network_policy_applied"),
                "status": "stub",
                "note": "v0 CLI skeleton; no model called, no role executed",
            }
            if override:
                entry["override_model"] = {
                    "model_id": override["model_id"],
                    **({"family": override["family"]} if "family" in override else {}),
                }
            invocations.append(entry)

    return {
        "bundle_id": bundle.get("bundle_id"),
        "cve_id": bundle.get("cve_id"),
        "bundle_kind": bundle.get("kind"),
        "nixpkgs_rev": bundle.get("nixpkgs_rev"),
        "policy_version": bundle.get("policy_version"),
        "bundle_schema_version": bundle.get("bundle_schema_version"),
        "bundle_dir": str(bundle_dir) if bundle_dir else None,
        "overrides_requested": overrides,
        "invocations": invocations,
        "executor": "stub",
    }


def _emit_plan(plan: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(plan, indent=2))
        return
    print(f"bundle_id:   {plan['bundle_id']}")
    print(f"cve_id:      {plan['cve_id']}")
    print(f"kind:        {plan['bundle_kind']}")
    print(f"nixpkgs_rev: {plan['nixpkgs_rev']}")
    if plan.get("bundle_dir"):
        print(f"bundle_dir:  {plan['bundle_dir']}")
    if plan["overrides_requested"]:
        print(f"overrides:   {json.dumps(plan['overrides_requested'], sort_keys=True)}")
    print(f"executor:    {plan['executor']} (no model calls, no network)")
    print()
    print(f"{len(plan['invocations'])} invocation(s):")
    for i, inv in enumerate(plan["invocations"], 1):
        mark = "→" if inv.get("override_model") else " "
        line = (
            f"  {mark} [{i:02d}] role={inv['role']:<22} "
            f"model={inv['original_model']['model_id']}"
        )
        if inv.get("override_model"):
            line += f"  (override → {inv['override_model']['model_id']})"
        print(line)
        print(
            f"        invocation_id={inv['invocation_id']}  "
            f"prompt_sha256={inv['prompt_sha256'][:12]}…  "
            f"network={inv['network_policy_applied']}"
        )
