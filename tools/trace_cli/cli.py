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

    from tools.trace_cli import pr as _pr_module
    _pr_module.add_parser(subs)

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
    r.add_argument(
        "--nixpkgs-checkout",
        type=Path,
        default=None,
        help=(
            "path to a working copy of nixpkgs (already at the bundle's "
            "pinned nixpkgs_rev, with any required patches applied or "
            "left for Builder to apply). Only consumed by the builder "
            "role; passed through to run_builder so patch-apply and "
            "passthru-tests enumeration run against this checkout. "
            "When omitted, Builder skips patch-apply and passthru "
            "enumeration (matches the current darwin-side behaviour)."
        ),
    )
    r.add_argument(
        "--builder-timeout",
        type=int,
        default=None,
        help=(
            "per-build timeout in seconds for the builder role's nix-build "
            "invocations (default 1800 / 30 min, hard-coded in run_builder). "
            "Bump this for slow-check packages like libtiff where the "
            "default trips on the patched-build sanity check despite the "
            "underlying derivation being fine. Only consumed by the "
            "builder role."
        ),
    )
    r.add_argument(
        "--reviewer-prompt",
        type=Path,
        default=None,
        help=(
            "override the Reviewer system prompt file for --execute --role reviewer "
            "(default: the pinned REVIEWER_PROMPT_PATH_DEFAULT). Records the chosen "
            "prompt path + sha256 in the invocation, so a regeneration wave under a "
            "new prompt version is explicit and auditable. Only consumed by the "
            "reviewer role."
        ),
    )

    b = subs.add_parser("bundle", help="bundle-assembly tooling")
    b_subs = b.add_subparsers(dest="bundle_cmd", required=True)
    b_asm = b_subs.add_parser(
        "assemble",
        help=(
            "glue resolver-side pieces into a partial bundle dir. v0: "
            "runs UpstreamRefResolver + URL derivation + URL prefetch + "
            "(optionally) go-mod-vendor; writes upstream-ref.json with "
            "prefetch_hashes[] and prefetch_skips[] populated. Does NOT "
            "call Patcher and does NOT synthesise Scout/Cartographer."
        ),
    )
    b_asm.add_argument("--input", type=Path, required=True,
                       help="path to resolver-input.json")
    b_asm.add_argument("--package", type=Path, required=True,
                       help="path to package.nix for the affected attr")
    b_asm.add_argument("--out", type=Path, required=True,
                       help="output directory (created if missing)")
    b_asm.add_argument("--finding", type=Path, default=None,
                       help="optional finding.json to copy in verbatim")
    b_asm.add_argument("--impact", type=Path, default=None,
                       help="optional impact.json to copy in verbatim")
    b_asm.add_argument("--maintainers", type=Path, default=None,
                       help="optional maintainers.json to copy in verbatim")
    b_asm.add_argument("--attr", default=None,
                       help="affected attr_path (e.g. 'traefik'); falls back to "
                            "resolver-input's attr_path field")
    b_asm.add_argument("--nixpkgs-rev", default=None,
                       help="nixpkgs revision for go-mod-vendor pinning")
    b_asm.add_argument("--go-mod-vendor", action="store_true",
                       help="run live go-mod-vendor for vendorHash slots "
                            "(slow; off by default)")
    b_asm.add_argument("--fetchzip", action="store_true",
                       help="run live fetchzip src.hash extraction for "
                            "fetchFromGitHub / fetchzip / fetchgit packages "
                            "(slow; off by default). Required when the "
                            "package uses any fetcher whose hash is NOT "
                            "the raw download hash.")
    b_asm.add_argument("--format", choices=("human", "json"), default="human")

    b_fin = b_subs.add_parser(
        "finalize",
        help=(
            "compute file hashes + write bundle.json + replay.json against "
            "an already-assembled bundle dir. Pairs with `bundle assemble`: "
            "assemble produces the resolver-side artifacts; finalize "
            "produces the manifest + replay record so `replay --execute` "
            "can run downstream against the bundle."
        ),
    )
    b_fin.add_argument("--bundle-dir", type=Path, required=True,
                       help="bundle directory previously produced by assemble")
    b_fin.add_argument("--kind", default="auto-merge",
                       choices=("auto-merge", "advisory-only", "human-review-required"))
    b_fin.add_argument("--kind-reason", default=None,
                       help="kind_reason code for non-auto-merge bundles. "
                            "Defaults derived from upstream-ref.json's "
                            "eligibility.human_review_trigger when omitted.")
    b_fin.add_argument("--created-at", default=None,
                       help="override created_at timestamp (default: now UTC)")
    b_fin.add_argument("--nixpkgs-rev", default=None,
                       help="override nixpkgs_rev (default: read from impact.json)")
    b_fin.add_argument("--cve-id", default=None,
                       help="override cve_id (default: read from upstream-ref.json)")
    b_fin.add_argument("--evidence-path", default=None,
                       choices=("reproducer", "reviewer-attested"),
                       help="auto_merge_evidence_path override (default: preserve from existing bundle.json)")
    b_fin.add_argument("--format", choices=("human", "json"), default="human")

    from tools.trace_cli import verify as _verify_module
    _verify_module.add_parser(b_subs)

    from tools.trace_cli import pr_snippet as _pr_snippet_module
    _pr_snippet_module.add_parser(b_subs)

    rp = subs.add_parser("report", help="rollup reports over on-disk artifacts")
    rp_subs = rp.add_subparsers(dest="report_cmd", required=True)
    from tools.trace_cli import report as _report_module
    _report_module.add_parser(rp_subs)

    from tools.trace_cli import export as _export_module
    _export_module.add_parser(subs)

    from tools.trace_cli import mutate as _mutate_module
    _mutate_module.add_parser(subs)

    from tools.trace_cli import backport_patch as _backport_module
    _backport_module.add_parser(subs)
    _backport_module.add_fixtures_parser(subs)

    e = subs.add_parser("eval", help="cohort-level evaluation tooling")
    e_subs = e.add_subparsers(dest="eval_cmd", required=True)
    e_pr = e_subs.add_parser(
        "patch-rate",
        help=(
            "aggregate scoring-report.json files into a cohort report. "
            "Walks the supplied glob, filters to dispatchable bundles "
            "(dispatch-guarded cases have no scoring-report.json by "
            "construction), emits patch_rate + merge-ready-rate mean + "
            "per-scorer means + per-invocation provenance."
        ),
    )
    e_pr.add_argument("--cohort", required=True,
                      help="cohort label. Recommended: synthetic | real-single "
                           "| inner-loop | full-corpus. Free-form strings "
                           "accepted; the four above are the documented baselines.")
    e_pr.add_argument("--reports", required=True,
                      help="glob expression matching scoring-report.json files")
    e_pr.add_argument("--format", choices=("human", "json"), default="human")

    e_rr = e_subs.add_parser(
        "review-rate",
        help=(
            "aggregate review-scoring-report.json files into a cohort-level "
            "reviewer report. v0 fields: accept/reject/escalate rates, "
            "evidence-cited mean, attestation-correct rate, reviewer-steward "
            "disagreement rate, provenance per run."
        ),
    )
    e_rr.add_argument("--cohort", required=True,
                      help="cohort label. Recommended: synthetic | real-single "
                           "| inner-loop | full-corpus | real-ci-smoke. Free-form "
                           "strings accepted.")
    e_rr.add_argument("--reports", required=True,
                      help="glob expression matching review-scoring-report.json files")
    e_rr.add_argument("--format", choices=("human", "json"), default="human")

    e_repro = e_subs.add_parser(
        "repro-rate",
        help=(
            "aggregate repro-scoring-report.json files into a cohort-level "
            "reproducer report. v0 fields: well-formed rate, vuln-signal-"
            "recovered rate, proxy-patched-passes rate, passthru-coverage mean, "
            "proxy rate + reason distribution, refusal rate, signal-specificity "
            "mean (advisory), provenance per run."
        ),
    )
    e_repro.add_argument(
        "--cohort", required=True,
        help="cohort label. Recommended: synthetic | real-single | inner-loop | "
             "full-corpus | real-ci-smoke. Free-form strings accepted.",
    )
    e_repro.add_argument(
        "--reports", required=True,
        help="glob expression matching repro-scoring-report.json files",
    )
    e_repro.add_argument(
        "--format", choices=("human", "json"), default="human",
    )

    args = parser.parse_args(argv)
    if args.cmd == "pr":
        from tools.trace_cli import pr as _pr_module
        return _pr_module.run(args)
    if args.cmd == "export":
        from tools.trace_cli import export as _export_module
        return _export_module.run(args)
    if args.cmd == "mutate":
        from tools.trace_cli import mutate as _mutate_module
        return _mutate_module.run(args)
    if args.cmd == "backport-patch":
        from tools.trace_cli import backport_patch as _backport_module
        return _backport_module.run(args)
    if args.cmd == "backport-fixtures":
        from tools.trace_cli import backport_patch as _backport_module
        return _backport_module.run_fixtures(args)
    if args.cmd == "replay":
        return _cmd_replay(args)
    if args.cmd == "review":
        if args.review_cmd == "summarize":
            return _cmd_review_summarize(args)
        return EXIT_USAGE
    if args.cmd == "bundle":
        if args.bundle_cmd == "assemble":
            return _cmd_bundle_assemble(args)
        if args.bundle_cmd == "finalize":
            return _cmd_bundle_finalize(args)
        if args.bundle_cmd == "verify":
            from tools.trace_cli import verify as _verify_module
            from pathlib import Path as _Path
            return _verify_module.run(args, repo_root=_Path(__file__).resolve().parents[2])
        if args.bundle_cmd == "pr-snippet":
            from tools.trace_cli import pr_snippet as _pr_snippet_module
            return _pr_snippet_module.run(args)
        return EXIT_USAGE
    if args.cmd == "report":
        if args.report_cmd == "throughput":
            from tools.trace_cli import report as _report_module
            from pathlib import Path as _Path
            return _report_module.run(args, repo_root=_Path(__file__).resolve().parents[2])
        return EXIT_USAGE
    if args.cmd == "eval":
        if args.eval_cmd == "patch-rate":
            return _cmd_eval_patch_rate(args)
        if args.eval_cmd == "review-rate":
            return _cmd_eval_review_rate(args)
        if args.eval_cmd == "repro-rate":
            return _cmd_eval_repro_rate(args)
        return EXIT_USAGE
    return EXIT_USAGE


def _cmd_eval_repro_rate(args: argparse.Namespace) -> int:
    from agents.scorers.reproducer_aggregator import (
        KNOWN_REPRODUCER_COHORT_LABELS,
        aggregate_reproducer_reports,
        expand_reproducer_glob,
    )

    paths = expand_reproducer_glob(args.reports)
    if not paths:
        print(
            f"error: no repro-scoring-report.json files matched glob {args.reports!r}",
            file=sys.stderr,
        )
        return EXIT_INVALID

    result = aggregate_reproducer_reports(report_paths=paths, cohort=args.cohort)

    if args.format == "json":
        payload = result.to_dict()
        if args.cohort not in KNOWN_REPRODUCER_COHORT_LABELS:
            payload["cohort_label_recognised"] = False
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    def _fmt(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.3f}"

    label_note = "" if args.cohort in KNOWN_REPRODUCER_COHORT_LABELS else \
                 " (free-form label; not in KNOWN_REPRODUCER_COHORT_LABELS)"
    print(f"cohort:                            {result.cohort}{label_note}")
    print(f"aggregated_at:                     {result.aggregated_at}")
    print(f"scoring_reports:                   {result.totals['scoring_reports']}")
    print(f"  parse_errors:                    {result.totals['parse_errors']}")
    print(f"  refusals:                        {result.totals['refusals']}")
    print(f"  proxy:                           {result.totals['proxy']}")
    print(f"  vuln_signal_eligible:            {result.totals['vuln_signal_eligible']}")
    print(f"  proxy_eligible:                  {result.totals['proxy_eligible']}")
    print(f"reproducer_well_formed_rate:       {_fmt(result.reproducer_well_formed_rate)}")
    print(f"vuln_signal_recovered_rate:       {_fmt(result.vuln_signal_recovered_rate)}")
    print(f"proxy_patched_passes_rate:         {_fmt(result.proxy_patched_passes_rate)}")
    print(f"passthru_coverage_mean:            {_fmt(result.passthru_coverage_mean)}")
    print(f"proxy_rate:                        {_fmt(result.proxy_rate)}")
    print(f"refusal_rate:                      {_fmt(result.refusal_rate)}")
    print(f"signal_specificity_mean (advisory):")
    print(f"                                   {_fmt(result.signal_specificity_mean)}")
    if result.proxy_reason_distribution:
        print("proxy_reason_distribution:")
        for reason in sorted(result.proxy_reason_distribution):
            print(f"  {reason:42s} {result.proxy_reason_distribution[reason]}")
    return EXIT_OK


def _cmd_eval_review_rate(args: argparse.Namespace) -> int:
    from agents.scorers.reviewer_aggregator import (
        KNOWN_REVIEWER_COHORT_LABELS,
        aggregate_reviewer_reports,
        expand_review_glob,
    )

    paths = expand_review_glob(args.reports)
    if not paths:
        print(
            f"error: no review-scoring-report.json files matched glob {args.reports!r}",
            file=sys.stderr,
        )
        return EXIT_INVALID

    result = aggregate_reviewer_reports(report_paths=paths, cohort=args.cohort)

    if args.format == "json":
        payload = result.to_dict()
        if args.cohort not in KNOWN_REVIEWER_COHORT_LABELS:
            payload["cohort_label_recognised"] = False
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    def _fmt(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.3f}"

    label_note = "" if args.cohort in KNOWN_REVIEWER_COHORT_LABELS else \
                 " (free-form label; not in KNOWN_REVIEWER_COHORT_LABELS)"
    print(f"cohort:                       {result.cohort}{label_note}")
    print(f"aggregated_at:                {result.aggregated_at}")
    print(f"scoring_reports:              {result.totals['scoring_reports']}")
    print(f"  parse_errors:               {result.totals['parse_errors']}")
    print(f"  verdicts:                   {result.totals['verdicts']}")
    print(f"  refusals:                   {result.totals['refusals']}")
    print(f"  accept / reject / escalate: "
          f"{result.totals['accept']} / {result.totals['reject']} / {result.totals['escalate']}")
    print(f"accept_rate:                  {_fmt(result.accept_rate)}")
    print(f"reject_rate:                  {_fmt(result.reject_rate)}")
    print(f"escalate_rate:                {_fmt(result.escalate_rate)}")
    print(f"evidence_cited_mean:          {_fmt(result.evidence_cited_mean)}")
    print(f"attestation_correct_rate:     {_fmt(result.attestation_correct_rate)}")
    print(f"reviewer_steward_disagreement_rate (informational):")
    print(f"                              {_fmt(result.reviewer_steward_disagreement_rate)}")
    return EXIT_OK


def _cmd_eval_patch_rate(args: argparse.Namespace) -> int:
    from agents.scorers import (
        KNOWN_COHORT_LABELS,
        aggregate_reports,
        expand_glob,
    )

    paths = expand_glob(args.reports)
    if not paths:
        print(
            f"error: no scoring-report.json files matched glob {args.reports!r}",
            file=sys.stderr,
        )
        return EXIT_INVALID

    result = aggregate_reports(report_paths=paths, cohort=args.cohort)

    if args.format == "json":
        payload = result.to_dict()
        if args.cohort not in KNOWN_COHORT_LABELS:
            payload["cohort_label_recognised"] = False
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    pr = "n/a" if result.patch_rate is None else f"{result.patch_rate:.3f}"
    mr = "n/a" if result.merge_ready_rate_mean is None else f"{result.merge_ready_rate_mean:.3f}"
    print(f"cohort:                 {result.cohort}"
          f"{'' if args.cohort in KNOWN_COHORT_LABELS else ' (free-form label; not in KNOWN_COHORT_LABELS)'}")
    print(f"aggregated_at:          {result.aggregated_at}")
    print(f"scoring_reports:        {result.totals['scoring_reports']}")
    print(f"  parse_errors:         {result.totals['parse_errors']}")
    print(f"  dispatchable:         {result.totals['dispatchable']}")
    print(f"  patches:              {result.totals['patches']}")
    print(f"    at threshold ≥0.95: {result.totals['patches_at_threshold']}")
    print(f"  refusals:             {result.totals['refusals']}")
    print(f"patch_rate:             {pr}")
    print(f"merge-ready rate mean:  {mr}")
    if result.scorer_means:
        print("scorer means (over invocations where applies=True):")
        for name in sorted(result.scorer_means):
            v = result.scorer_means[name]
            print(f"  {name:30s} {('n/a' if v is None else f'{v:.3f}')}")
    return EXIT_OK


def _cmd_bundle_finalize(args: argparse.Namespace) -> int:
    from tools.trace_cli.bundle import emit_finalize_summary, finalize_bundle

    try:
        result = finalize_bundle(
            bundle_dir=args.bundle_dir,
            bundle_kind=args.kind,
            kind_reason=args.kind_reason,
            created_at=args.created_at,
            nixpkgs_rev=args.nixpkgs_rev,
            cve_id=args.cve_id,
            auto_merge_evidence_path=getattr(args, "evidence_path", None),
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"error: finalize failed: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(emit_finalize_summary(result))
    return EXIT_OK


def _cmd_bundle_assemble(args: argparse.Namespace) -> int:
    from tools.trace_cli.bundle import assemble_bundle, emit_human_summary

    try:
        result = assemble_bundle(
            resolver_input_path=args.input,
            package_nix_path=args.package,
            out_dir=args.out,
            finding_path=args.finding,
            impact_path=args.impact,
            maintainers_path=args.maintainers,
            attr_path=args.attr,
            nixpkgs_rev=args.nixpkgs_rev,
            run_go_mod_vendor=args.go_mod_vendor,
            run_fetchzip=args.fetchzip,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"error: assembly failed: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(emit_human_summary(result))
    return EXIT_OK


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
    from tools.trace_cli.execute import (
        ExecutionError,
        HashMismatch,
        MODEL_BACKED_ROLES,
        PatcherDispatchRefused,
        execute,
    )

    # Resolve model_id: --model wins; otherwise look it up in
    # --routing-config; otherwise fail.
    resolved_model_id: str | None = args.model
    if (
        args.role in MODEL_BACKED_ROLES
        and resolved_model_id is None
        and args.routing_config is not None
    ):
        try:
            rc = json.loads(args.routing_config.read_text())
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"error: cannot read --routing-config: {exc}", file=sys.stderr)
            return EXIT_INVALID
        spec = rc.get(args.role) if isinstance(rc, dict) else None
        if isinstance(spec, dict) and isinstance(spec.get("model_id"), str):
            resolved_model_id = spec["model_id"]
    if args.role in MODEL_BACKED_ROLES and not resolved_model_id:
        print(
            f"error: --execute --role {args.role} requires --model <id> "
            f"(or --routing-config containing an entry for {args.role!r}; "
            f"no default live model; explicit by design)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    role_entry = None
    for entry in replay.get("roles", []):
        if entry.get("role") == args.role:
            role_entry = entry
            break

    # For model-backed fresh runs AND runner-backed (Builder) reruns, a
    # missing role entry is acceptable: we synthesise a single fresh
    # invocation. Builder by design produces a new invocation per run
    # (build.json + replay.json append); requiring a pre-recorded entry
    # would block first-time runs against any bundle. Cartographer /
    # UpstreamRefResolver remain strict: missing entries are EXIT_NOT_FOUND
    # because their outputs are recorded as part of the bundle's frozen
    # provenance and there is no "fresh-run" semantic for them at this
    # layer.
    from tools.trace_cli.execute import RUNNER_BACKED_ROLES
    _fresh_run_eligible = MODEL_BACKED_ROLES | RUNNER_BACKED_ROLES
    if role_entry is None:
        if args.role in _fresh_run_eligible:
            role_entry = {
                "role": args.role,
                "invocations": [
                    {"invocation_id": None, "inputs": [], "outputs": []}
                ],
            }
        else:
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
                model_id=resolved_model_id,
                nixpkgs_checkout=args.nixpkgs_checkout,
                builder_timeout_seconds=args.builder_timeout,
                reviewer_prompt_path=getattr(args, "reviewer_prompt", None),
            )
        except HashMismatch as exc:
            print(f"hash-mismatch: {exc}", file=sys.stderr)
            return EXIT_HASH_MISMATCH
        except PatcherDispatchRefused as exc:
            # Dispatch refusal is a distinct signal from "bad input": the
            # bundle is fine, Patcher just must not run on it. Exit non-zero
            # but with EXIT_INVALID so CI sees it.
            print(f"dispatch-refused: {exc}", file=sys.stderr)
            return EXIT_INVALID
        except ExecutionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID
        results.append(result)

    # Patcher (model-backed) outputs have shape {path, sha256, bytes} — no
    # declared sha to compare against because the content is freshly produced.
    # Deterministic role outputs have shape {path, declared_sha256,
    # computed_sha256}. Normalise both into the emit shape so the printer
    # (and JSON consumers) can handle either path uniformly.
    def _normalise_output(o: dict[str, Any]) -> dict[str, Any]:
        if "declared_sha256" in o:
            return {
                "path": o["path"],
                "declared_sha256": o["declared_sha256"],
                "computed_sha256": o["computed_sha256"],
                "match": o["declared_sha256"] == o["computed_sha256"],
            }
        return {
            "path": o["path"],
            "declared_sha256": None,
            "computed_sha256": o.get("sha256"),
            "match": None,
        }

    _emit_execute_results(
        {
            "bundle_id": bundle.get("bundle_id"),
            "cve_id": bundle.get("cve_id"),
            "role": args.role,
            "verified": not args.no_verify,
            "executor": "deterministic-stub" if args.role not in MODEL_BACKED_ROLES else "model-backed",
            "results": [
                {
                    "invocation_id": r["invocation_id"],
                    "outputs": [_normalise_output(o) for o in r["outputs"]],
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
            if o["match"] is True:
                mark = "✓"
            elif o["match"] is False:
                mark = "✗"
            else:
                mark = "·"  # fresh model-backed output: no declared sha to compare
            computed = (o.get("computed_sha256") or "?")[:12]
            declared = o.get("declared_sha256")
            tail = f" declared={declared[:12]}…" if declared else " (fresh)"
            print(f"  {mark} {o['path']}  computed={computed}…{tail}")


def _validate_override_args(args: argparse.Namespace) -> str | None:
    # --routing-config is the canonical role-to-model lookup for live runs.
    # When supplied with --execute and --role, the model_id is resolved
    # from the config rather than from --model. Supplying --model and
    # --routing-config together is still ambiguous (which one wins?), so
    # disallow that explicit conflict.
    if args.routing_config and args.model:
        return "--routing-config is mutually exclusive with --model"
    if args.execute:
        if not args.role:
            return "--execute requires --role"
        # --execute now accepts --routing-config provided --role is given.
        # The role-specific model_id is looked up from the config.
        return None
    if args.role and not args.model and not args.routing_config:
        return "--role requires --model (or --routing-config)"
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
