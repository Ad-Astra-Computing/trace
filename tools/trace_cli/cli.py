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
    r.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help=(
            "override the model output budget (sampling.max_tokens, default 8192) "
            "for --execute --role patcher|reviewer. Use when a large upstream fix "
            "truncates the two-block output (the failure lands in "
            ".<role>-failures/<uuid>/raw-response.txt). The value used is recorded "
            "in the invocation's sampling block."
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
    b_asm.add_argument(
        "--input", type=Path, required=True, help="path to resolver-input.json"
    )
    b_asm.add_argument(
        "--package",
        type=Path,
        required=True,
        help="path to package.nix for the affected attr",
    )
    b_asm.add_argument(
        "--out", type=Path, required=True, help="output directory (created if missing)"
    )
    b_asm.add_argument(
        "--finding",
        type=Path,
        default=None,
        help="optional finding.json to copy in verbatim",
    )
    b_asm.add_argument(
        "--impact",
        type=Path,
        default=None,
        help="optional impact.json to copy in verbatim",
    )
    b_asm.add_argument(
        "--maintainers",
        type=Path,
        default=None,
        help="optional maintainers.json to copy in verbatim",
    )
    b_asm.add_argument(
        "--attr",
        default=None,
        help="affected attr_path (e.g. 'traefik'); falls back to "
        "resolver-input's attr_path field",
    )
    b_asm.add_argument(
        "--nixpkgs-rev", default=None, help="nixpkgs revision for go-mod-vendor pinning"
    )
    b_asm.add_argument(
        "--go-mod-vendor",
        action="store_true",
        help="run live go-mod-vendor for vendorHash slots (slow; off by default)",
    )
    b_asm.add_argument(
        "--fetchzip",
        action="store_true",
        help="run live fetchzip src.hash extraction for "
        "fetchFromGitHub / fetchzip / fetchgit packages "
        "(slow; off by default). Required when the "
        "package uses any fetcher whose hash is NOT "
        "the raw download hash.",
    )
    b_asm.add_argument(
        "--upstream-fix-patch",
        type=Path,
        default=None,
        help="source-backport only: the upstream fix commit diff "
        "(ground truth). Copied in as upstream-fix.patch; when "
        "a source tree is available also drives source-context/ "
        "extraction + the applies_verbatim preflight verdict.",
    )
    b_asm.add_argument(
        "--source-tree",
        type=Path,
        default=None,
        help="pre-unpacked pinned source root for source-context "
        "extraction (skips the nix unpack; use offline or when "
        "you already have the source, e.g. from preflight).",
    )
    b_asm.add_argument(
        "--source-context",
        action="store_true",
        help="source-backport only: extract source-context/ from the "
        "pinned pkg.src (nix unpack; slow, network). Implied "
        "when --source-tree is given.",
    )
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
    b_fin.add_argument(
        "--bundle-dir",
        type=Path,
        required=True,
        help="bundle directory previously produced by assemble",
    )
    b_fin.add_argument(
        "--kind",
        default="auto-merge",
        choices=("auto-merge", "advisory-only", "human-review-required"),
    )
    b_fin.add_argument(
        "--kind-reason",
        default=None,
        help="kind_reason code for non-auto-merge bundles. "
        "Defaults derived from upstream-ref.json's "
        "eligibility.human_review_trigger when omitted.",
    )
    b_fin.add_argument(
        "--created-at",
        default=None,
        help="override created_at timestamp (default: now UTC)",
    )
    b_fin.add_argument(
        "--nixpkgs-rev",
        default=None,
        help="override nixpkgs_rev (default: read from impact.json)",
    )
    b_fin.add_argument(
        "--cve-id",
        default=None,
        help="override cve_id (default: read from upstream-ref.json)",
    )
    b_fin.add_argument(
        "--evidence-path",
        default=None,
        choices=("reproducer", "reviewer-attested"),
        help="auto_merge_evidence_path override (default: preserve from existing bundle.json)",
    )
    b_fin.add_argument(
        "--gate-sourceroot",
        action="store_true",
        help="opt-in: for a source-backport bundle with patch.diff "
        "already on disk, fail closed unless it applies -p1 "
        "from the derivation's EFFECTIVE sourceRoot (catches "
        "a path-strip mismatch before cert dispatch). Requires "
        "nix + network unless --gate-source-tree is given.",
    )
    b_fin.add_argument(
        "--gate-source-tree",
        type=Path,
        default=None,
        help="pre-unpacked EFFECTIVE source root for "
        "--gate-sourceroot (skips the nix unpack)",
    )
    b_fin.add_argument(
        "--gate-patch-flags",
        type=str,
        default=None,
        metavar="FLAGS",
        help="(with --gate-source-tree) the package's patchFlags "
        "as one whitespace-separated string, `=` form so "
        "argparse accepts dashes, e.g. --gate-patch-flags=-p0. "
        "Without it a supplied tree is gated at -p1; ignored "
        "on the nix-unpack path (evaluated patchFlags win).",
    )
    b_fin.add_argument(
        "--supersede-signature",
        action="store_true",
        help="allow finalize to rewrite the manifest of an already-signed "
        "bundle (bundle.sig present). Archives the current signature's "
        "Rekor coordinates into superseded-signatures.json first; the "
        "bundle is unsigned again until Steward re-signs it.",
    )
    b_fin.add_argument("--format", choices=("human", "json"), default="human")

    from tools.trace_cli import verify as _verify_module

    _verify_module.add_parser(b_subs)

    from tools.trace_cli import pr_snippet as _pr_snippet_module

    _pr_snippet_module.add_parser(b_subs)

    from tools.trace_cli import preflight as _preflight_module

    _preflight_module.add_parser(b_subs)

    from tools.trace_cli import bootstrap as _bootstrap_module

    _bootstrap_module.add_parser(b_subs)

    from tools.trace_cli import probe as _probe_module

    _probe_module.add_parser(b_subs)

    from tools.trace_cli import normalize_sourceroot as _normalize_module

    _normalize_module.add_parser(b_subs)

    from tools.trace_cli import normalize_context as _normalize_ctx_module

    _normalize_ctx_module.add_parser(b_subs)

    from tools.trace_cli import rationale_binding as _rationale_binding_module

    _rationale_binding_module.add_parser(b_subs)

    cand = subs.add_parser("candidate", help="work one screened candidate end to end")
    cand_subs = cand.add_subparsers(dest="candidate_cmd", required=True)
    from tools.trace_cli import candidate_run as _candidate_run_module

    _candidate_run_module.add_parser(cand_subs)

    cmp = subs.add_parser(
        "compare", help="compare live-lane bundles against what nixpkgs lands"
    )
    cmp_subs = cmp.add_subparsers(dest="compare_cmd", required=True)
    from tools.trace_cli import compare_watch as _compare_watch_module

    _compare_watch_module.add_parser(cmp_subs)

    rp = subs.add_parser("report", help="rollup reports over on-disk artifacts")
    rp_subs = rp.add_subparsers(dest="report_cmd", required=True)
    from tools.trace_cli import report as _report_module

    _report_module.add_parser(rp_subs)

    rs = subs.add_parser("reproducer", help="reproducer-stage tooling")
    rs_subs = rs.add_subparsers(dest="reproducer_cmd", required=True)
    from tools.trace_cli import reproducer_sample as _reproducer_sample_module

    _reproducer_sample_module.add_parser(rs_subs)

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
    e_pr.add_argument(
        "--cohort",
        required=True,
        help="cohort label. Recommended: synthetic | real-single "
        "| inner-loop | full-corpus. Free-form strings "
        "accepted; the four above are the documented baselines.",
    )
    e_pr.add_argument(
        "--reports",
        required=True,
        help="glob expression matching scoring-report.json files",
    )
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
    e_rr.add_argument(
        "--cohort",
        required=True,
        help="cohort label. Recommended: synthetic | real-single "
        "| inner-loop | full-corpus | real-ci-smoke. Free-form "
        "strings accepted.",
    )
    e_rr.add_argument(
        "--reports",
        required=True,
        help="glob expression matching review-scoring-report.json files",
    )
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
        "--cohort",
        required=True,
        help="cohort label. Recommended: synthetic | real-single | inner-loop | "
        "full-corpus | real-ci-smoke. Free-form strings accepted.",
    )
    e_repro.add_argument(
        "--reports",
        required=True,
        help="glob expression matching repro-scoring-report.json files",
    )
    e_repro.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
    )

    sc = subs.add_parser(
        "score", help="scorer-run tooling (produces scoring-report.json artifacts)"
    )
    sc_subs = sc.add_subparsers(dest="score_cmd", required=True)
    sc_rv = sc_subs.add_parser(
        "review",
        help=(
            "run the reviewer scorer set (canonical five + adaptation-"
            "equivalence) against a bundle's last reviewer invocation "
            "and write review-scoring-report.json"
        ),
    )
    sc_rv.add_argument("bundle_dir", type=Path, help="bundle directory")
    sc_rv.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing review-scoring-report.json",
    )
    sc_rv.add_argument("--format", choices=("text", "json"), default="text")
    sc_rv.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="output path (default: <bundle_dir>/review-scoring-report.json)",
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
    if args.cmd == "reproducer":
        if args.reproducer_cmd == "sample":
            from tools.trace_cli import reproducer_sample as _reproducer_sample_module

            return _reproducer_sample_module.run(args)
        return EXIT_USAGE
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

            return _verify_module.run(
                args, repo_root=_Path(__file__).resolve().parents[2]
            )
        if args.bundle_cmd == "pr-snippet":
            from tools.trace_cli import pr_snippet as _pr_snippet_module

            return _pr_snippet_module.run(args)
        if args.bundle_cmd == "probe":
            from tools.trace_cli import probe as _probe_module

            return _probe_module.run(args)
        if args.bundle_cmd == "bootstrap":
            from tools.trace_cli import bootstrap as _bootstrap_module

            return _bootstrap_module.run(args)
        if args.bundle_cmd == "preflight":
            from tools.trace_cli import preflight as _preflight_module
            from pathlib import Path as _Path

            return _preflight_module.run(
                args, repo_root=_Path(__file__).resolve().parents[2]
            )
        if args.bundle_cmd == "normalize-sourceroot":
            from tools.trace_cli import normalize_sourceroot as _normalize_module
            from pathlib import Path as _Path

            return _normalize_module.run(
                args, repo_root=_Path(__file__).resolve().parents[2]
            )
        if args.bundle_cmd == "rationale-binding":
            from tools.trace_cli import rationale_binding as _rationale_binding_module

            return _rationale_binding_module.run(args)
        if args.bundle_cmd == "normalize-context":
            from tools.trace_cli import normalize_context as _normalize_ctx_module
            from pathlib import Path as _Path

            return _normalize_ctx_module.run(
                args, repo_root=_Path(__file__).resolve().parents[2]
            )
        return EXIT_USAGE
    if args.cmd == "candidate":
        if args.candidate_cmd == "run":
            from tools.trace_cli import candidate_run as _candidate_run_module

            return _candidate_run_module.run(args)
        return EXIT_USAGE
    if args.cmd == "compare":
        from tools.trace_cli import compare_watch as _compare_watch_module

        return _compare_watch_module.run(args)
    if args.cmd == "report":
        if args.report_cmd == "throughput":
            from tools.trace_cli import report as _report_module
            from pathlib import Path as _Path

            return _report_module.run(
                args, repo_root=_Path(__file__).resolve().parents[2]
            )
        return EXIT_USAGE
    if args.cmd == "eval":
        if args.eval_cmd == "patch-rate":
            return _cmd_eval_patch_rate(args)
        if args.eval_cmd == "review-rate":
            return _cmd_eval_review_rate(args)
        if args.eval_cmd == "repro-rate":
            return _cmd_eval_repro_rate(args)
        return EXIT_USAGE
    if args.cmd == "score":
        if args.score_cmd == "review":
            return _cmd_score_review(args)
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

    label_note = (
        ""
        if args.cohort in KNOWN_REPRODUCER_COHORT_LABELS
        else " (free-form label; not in KNOWN_REPRODUCER_COHORT_LABELS)"
    )
    print(f"cohort:                            {result.cohort}{label_note}")
    print(f"aggregated_at:                     {result.aggregated_at}")
    print(f"scoring_reports:                   {result.totals['scoring_reports']}")
    print(f"  parse_errors:                    {result.totals['parse_errors']}")
    print(f"  refusals:                        {result.totals['refusals']}")
    print(f"  proxy:                           {result.totals['proxy']}")
    print(f"  vuln_signal_eligible:            {result.totals['vuln_signal_eligible']}")
    print(f"  proxy_eligible:                  {result.totals['proxy_eligible']}")
    print(
        f"reproducer_well_formed_rate:       {_fmt(result.reproducer_well_formed_rate)}"
    )
    print(
        f"vuln_signal_recovered_rate:       {_fmt(result.vuln_signal_recovered_rate)}"
    )
    print(
        f"proxy_patched_passes_rate:         {_fmt(result.proxy_patched_passes_rate)}"
    )
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

    label_note = (
        ""
        if args.cohort in KNOWN_REVIEWER_COHORT_LABELS
        else " (free-form label; not in KNOWN_REVIEWER_COHORT_LABELS)"
    )
    print(f"cohort:                       {result.cohort}{label_note}")
    print(f"aggregated_at:                {result.aggregated_at}")
    print(f"scoring_reports:              {result.totals['scoring_reports']}")
    print(f"  parse_errors:               {result.totals['parse_errors']}")
    print(f"  verdicts:                   {result.totals['verdicts']}")
    print(f"  refusals:                   {result.totals['refusals']}")
    print(
        f"  accept / reject / escalate: "
        f"{result.totals['accept']} / {result.totals['reject']} / {result.totals['escalate']}"
    )
    print(f"accept_rate:                  {_fmt(result.accept_rate)}")
    print(f"reject_rate:                  {_fmt(result.reject_rate)}")
    print(f"escalate_rate:                {_fmt(result.escalate_rate)}")
    print(f"evidence_cited_mean:          {_fmt(result.evidence_cited_mean)}")
    print(f"attestation_correct_rate:     {_fmt(result.attestation_correct_rate)}")
    print(f"patch_comparison_present_rate:")
    print(f"                              {_fmt(result.patch_comparison_present_rate)}")
    print(f"adaptation_equivalence_correct_rate:")
    print(
        f"                              {_fmt(result.adaptation_equivalence_correct_rate)}"
    )
    print(f"reviewer_steward_disagreement_rate (informational):")
    print(
        f"                              {_fmt(result.reviewer_steward_disagreement_rate)}"
    )
    return EXIT_OK


def _find_last_reviewer_invocation(replay: dict[str, Any]) -> dict[str, Any] | None:
    """Mirrors `agents.scorers.reviewer_scorers._patcher_family_from_replay`:
    walk replay.json's roles for the reviewer role and return its last
    recorded invocation, or None if no reviewer invocation is recorded.

    Tolerant of a malformed replay: a non-list `roles`, non-dict role
    entries, or a non-list/empty `invocations` are skipped rather than
    crashing (the caller has already confirmed `replay` is a dict)."""
    roles = replay.get("roles", [])
    if not isinstance(roles, list):
        return None
    for role in roles:
        if not isinstance(role, dict) or role.get("role") != "reviewer":
            continue
        invs = role.get("invocations")
        if not isinstance(invs, list) or not invs:
            continue
        last = invs[-1]
        # A non-dict final entry (scalar/null in a malformed replay) is not a
        # usable invocation record; treat it as "no reviewer invocation".
        return last if isinstance(last, dict) else None
    return None


# Canonical reviewer inputs — the bundle files the reviewer runner reads into
# the model context (see agents/reviewer/runner.py:assemble_user_content) and
# that the scorers subsequently re-read from disk. Any present on disk must be
# pinned (recorded + hash-verified) by the scored invocation. Kept in sync with
# the reviewer runner; NOT a superset of every file a scorer touches
# (bundle.json / replay.json are bundle context whose integrity is the signing
# layer's concern, and replay.json cannot record its own hash).
#
# Split by lane: the ALWAYS set is consumed by every reviewer run; the
# ADAPTATION-ONLY set (+ source-context/**) is consumed only when execution
# entered the adaptation lane (applies_verbatim != true). A verbatim
# source-backport that happens to carry preflight.json/patch-applicability.json
# never fed them to the reviewer, so requiring them there would falsely reject
# a valid recorded invocation.
_ALWAYS_REVIEWER_INPUTS: tuple[str, ...] = (
    "finding.json",
    "upstream-ref.json",
    "impact.json",
    "maintainers.json",
    "package.nix",
    "patch.diff",
    "patch-rationale.md",
    "upstream-fix.patch",
)
_ADAPTATION_ONLY_INPUTS: tuple[str, ...] = (
    "preflight.json",
    "patch-applicability.json",
)


def _safe_bundle_relpath(bundle_dir: Path, rel: str) -> bool:
    """True iff `rel` is a bundle-relative path that stays within bundle_dir.

    Rejects absolute paths and any path that (after resolving, which also
    follows symlinks) escapes the bundle. A recorded artifact path is
    attacker-influenced when scoring an untrusted bundle, so a traversal like
    ``../../secret`` must never be read (nor its hash prefix leaked)."""
    if os.path.isabs(rel):
        return False
    try:
        resolved = (bundle_dir / rel).resolve()
        resolved.relative_to(bundle_dir.resolve())
    except (ValueError, OSError):
        return False
    return True


def _verify_invocation_artifacts(
    bundle_dir: Path, invocation: dict[str, Any]
) -> str | None:
    """Confirm the on-disk bundle matches the artifacts the selected reviewer
    invocation actually recorded — BOTH the inputs it consumed (finding.json,
    upstream-ref.json, patch.diff, …) and the outputs it produced (review.md /
    review-refusal.json). Returns an error string on the first problem, or None
    when every recorded artifact verifies.

    Without this the command could attribute a score to the recorded model +
    invocation while the scorers actually evaluated evidence the model never
    saw (a modified input) or an output it never produced (a swapped
    review.md). Several scorers derive their result from the inputs, so both
    sides must be pinned.

    Policy: at least one recorded output must be verified, and every recorded
    entry (input or output) must be well-formed. A non-empty outputs list whose
    entries are malformed / omit path or sha256 is REJECTED rather than
    silently passed — an unverifiable record is not evidence.
    """
    from hashlib import sha256 as _sha256

    def _verify(entry: Any, kind: str) -> tuple[bool, str | None]:
        """Returns (verified_a_file, error). verified_a_file is True only when
        a real file was hashed and matched."""
        if not isinstance(entry, dict):
            return False, f"malformed {kind} record (not an object): {entry!r}"
        rel = entry.get("path")
        recorded = entry.get("sha256")
        if not isinstance(rel, str) or not rel or not isinstance(recorded, str):
            return False, (
                f"malformed {kind} record (missing/invalid path or sha256): {entry!r}"
            )
        if not _safe_bundle_relpath(bundle_dir, rel):
            return False, (
                f"unsafe {kind} path {rel!r} escapes the bundle; refusing to read"
            )
        f = bundle_dir / rel
        if not f.is_file():
            return False, f"recorded {kind} {rel!r} is missing from {bundle_dir}"
        actual = _sha256(f.read_bytes()).hexdigest()
        if actual != recorded:
            return False, (
                f"{rel} on disk (sha256={actual[:12]}…) does not match the "
                f"recorded invocation {kind} (sha256={recorded[:12]}…); the "
                f"bundle was modified after the reviewer run"
            )
        return True, None

    canonical_outputs = {"review.md", "review-refusal.json"}
    outputs = invocation.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        return "selected reviewer invocation records no outputs to verify"
    verified_paths: set[str] = set()
    for out in outputs:
        ok, err = _verify(out, "output")
        if err is not None:
            return err
        if ok and isinstance(out, dict):
            verified_paths.add(out.get("path"))
    # The scorers read review.md / review-refusal.json from disk; requiring that
    # a canonical reviewer output was RECORDED and VERIFIED stops a malformed
    # invocation from passing on an incidental non-review file (e.g. recording
    # finding.json as its sole output) while the scorers evaluate an unrelated
    # on-disk review.md the invocation never produced.
    if not (canonical_outputs & verified_paths):
        return (
            "selected reviewer invocation records no verified canonical output "
            "(review.md or review-refusal.json)"
        )

    # The scorers read mutable bundle inputs (finding.json, upstream-ref.json,
    # patch.diff, …). Require the invocation to RECORD those inputs and verify
    # each, so a stale invocation cannot be scored against evidence it never
    # consumed. Missing or empty inputs defeats the attribution guarantee and is
    # rejected; a present non-list value is malformed.
    inputs = invocation.get("inputs")
    if inputs is None:
        return "selected reviewer invocation records no inputs to verify"
    if not isinstance(inputs, list):
        return f"malformed inputs record (present but not a list): {inputs!r}"
    if not inputs:
        return "selected reviewer invocation records an empty inputs list"
    verified_inputs: set[str] = set()
    for inp in inputs:
        ok, err = _verify(inp, "input")
        if err is not None:
            return err
        if ok and isinstance(inp, dict):
            verified_inputs.add(inp.get("path"))

    # Recording a nonempty-but-partial input set would let an UN-recorded but
    # scorer-consumed reviewer input (e.g. patch.diff, upstream-ref.json) be
    # modified after the run and still scored under this invocation. Require
    # every canonical reviewer input that is PRESENT on disk to be among the
    # verified inputs. (These are exactly the files the reviewer runner reads;
    # bundle.json / replay.json are bundle context, not reviewer inputs, and
    # their integrity is the signing/`bundle verify` layer's concern — see the
    # score-review boundary note in docs/DECISIONS.md.)
    from agents.scorers.reviewer_scorers import _is_adaptation_lane

    adaptation = _is_adaptation_lane(bundle_dir)
    required = list(_ALWAYS_REVIEWER_INPUTS)
    if adaptation:
        required += list(_ADAPTATION_ONLY_INPUTS)
    unpinned = [
        name
        for name in required
        if (bundle_dir / name).is_file() and name not in verified_inputs
    ]
    # Only the adaptation lane feeds source-context/** to the reviewer (a
    # verbatim run never reads it); pin each present file there dynamically.
    if adaptation:
        sc_dir = bundle_dir / "source-context"
        if sc_dir.is_dir():
            for f in sorted(sc_dir.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(bundle_dir).as_posix()
                    if rel not in verified_inputs:
                        unpinned.append(rel)
    if unpinned:
        return (
            "reviewer inputs present on disk but not recorded/verified by the "
            f"selected invocation: {unpinned}; the invocation must pin every "
            "input the scorers read"
        )
    return None


def _atomic_write_text(target: Path, text: str) -> None:
    """Write text atomically to target via temp file + os.replace, matching
    the pattern in tools/trace_cli/execute.py's _atomic_write_bytes."""
    import tempfile

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except Exception:
            pass
        raise


def _cmd_score_review(args: argparse.Namespace) -> int:
    from agents.scorers.reviewer_runner import run_reviewer_scorers

    bundle_dir: Path = args.bundle_dir
    replay_path = bundle_dir / "replay.json"
    try:
        replay = json.loads(replay_path.read_text())
    except FileNotFoundError:
        print(f"error: {replay_path} not found", file=sys.stderr)
        return EXIT_NOT_FOUND
    except json.JSONDecodeError as exc:
        print(f"error: {replay_path} invalid JSON: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if not isinstance(replay, dict):
        print(
            f"error: {replay_path} is not a JSON object",
            file=sys.stderr,
        )
        return EXIT_INVALID

    invocation = _find_last_reviewer_invocation(replay)
    if invocation is None:
        print(
            f"error: no reviewer invocation found in {replay_path}",
            file=sys.stderr,
        )
        return EXIT_INVALID

    mismatch = _verify_invocation_artifacts(bundle_dir, invocation)
    if mismatch is not None:
        print(f"error: {mismatch}", file=sys.stderr)
        return EXIT_HASH_MISMATCH

    report = run_reviewer_scorers(bundle_dir=bundle_dir, invocation=invocation)

    out_path: Path = (
        args.out if args.out is not None else bundle_dir / "review-scoring-report.json"
    )
    if out_path.exists() and not args.force:
        print(
            f"error: {out_path} already exists; pass --force to overwrite",
            file=sys.stderr,
        )
        return EXIT_INVALID

    body = json.dumps(report.to_dict(), indent=2) + "\n"
    _atomic_write_text(out_path, body)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK

    print(f"bundle_dir: {report.bundle_dir}")
    print(f"bundle_id:  {report.bundle_id}")
    print(f"cve_id:     {report.cve_id}")
    print(f"report:     {out_path}")
    for s in report.scorers:
        d = s.to_dict()
        score_str = "n/a" if d["score"] is None else f"{d['score']:.3f}"
        print(
            f"  {d['scorer_name']:32s} applies={str(d['applies']):5s} score={score_str}"
        )
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
    mr = (
        "n/a"
        if result.merge_ready_rate_mean is None
        else f"{result.merge_ready_rate_mean:.3f}"
    )
    print(
        f"cohort:                 {result.cohort}"
        f"{'' if args.cohort in KNOWN_COHORT_LABELS else ' (free-form label; not in KNOWN_COHORT_LABELS)'}"
    )
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
            gate_sourceroot=getattr(args, "gate_sourceroot", False),
            gate_source_tree=getattr(args, "gate_source_tree", None),
            gate_patch_flags=(
                _gpf.split()
                if (_gpf := getattr(args, "gate_patch_flags", None))
                else None
            ),
            supersede_signature=getattr(args, "supersede_signature", False),
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
            upstream_fix_patch_path=args.upstream_fix_patch,
            source_tree=args.source_tree,
            write_source_context=args.source_context or args.source_tree is not None,
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
                "invocations": [{"invocation_id": None, "inputs": [], "outputs": []}],
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
                max_tokens=getattr(args, "max_tokens", None),
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
            "executor": "deterministic-stub"
            if args.role not in MODEL_BACKED_ROLES
            else "model-backed",
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


def _build_overrides(
    args: argparse.Namespace,
) -> tuple[dict[str, dict[str, str]], str | None]:
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
        return (
            "routing-config must be a JSON object mapping role -> { model_id, family? }"
        )
    if not rc:
        return "routing-config is empty; supply at least one role override"
    allowed_role_keys = set(ROLE_NAMES)
    for role, spec in rc.items():
        if role not in allowed_role_keys:
            return f"routing-config: {role!r} is not a known role (expected one of {sorted(allowed_role_keys)})"
        if not isinstance(spec, dict):
            return f"routing-config[{role}]: value must be an object"
        if (
            "model_id" not in spec
            or not isinstance(spec["model_id"], str)
            or not spec["model_id"]
        ):
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
