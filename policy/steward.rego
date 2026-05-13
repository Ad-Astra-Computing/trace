# Steward — deterministic merge-gate policy for trace bundles.
#
# Scope is intentionally narrow (v0 spine). Extensions arrive as new rules, not
# as revisions to existing ones. Each rule produces a machine-readable decision
# in `data.trace.steward.deny` with a stable rule id prefix (`rule-N-...`).
#
# Input shape (built by the test runner from bundle files):
#   input.bundle        — contents of bundle.json
#   input.finding       — contents of finding.json
#   input.upstream_ref  — contents of upstream-ref.json
#   input.replay        — contents of replay.json
#   input.provenance    — array of parsed lines from provenance.jsonl
#
# Authoritative decision keys:
#   data.trace.steward.deny   — set of { rule_id, message }
#   data.trace.steward.allow  — boolean, true iff deny is empty

package trace.steward

import rego.v1

default allow := false

allow if count(deny) == 0

# ─────────────────────────────────────────────────────────────────────────────
# rule-1: auto-merge requires every affected derivation to have high confidence
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	some a in input.finding.affected
	a.confidence != "high"
	decision := {
		"rule_id": "rule-1-auto-merge-requires-high-confidence",
		"message": sprintf(
			"auto-merge forbids confidence != high; got %q on attr %q",
			[a.confidence, a.attr_path],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-2: eligible-requires-human-review forbids auto-merge
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.upstream_ref.eligibility.verdict == "eligible-requires-human-review"
	decision := {
		"rule_id": "rule-2-auto-merge-forbidden-on-eligible-requires-human-review",
		"message": sprintf(
			"upstream-ref verdict %q forbids auto-merge",
			[input.upstream_ref.eligibility.verdict],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-3: auto-merge requires a cross-family Patcher/Reviewer pair
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.replay.cross_family_rule_honored == false
	decision := {
		"rule_id": "rule-3-auto-merge-requires-cross-family-pair",
		"message": "auto-merge forbidden when cross_family_rule_honored=false",
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-4: every replay-critical file MUST appear in signed_manifest.signed_files
#          with a matching sha256.
# ─────────────────────────────────────────────────────────────────────────────
signed_path_to_hash[p] := h if {
	some sf in input.bundle.signed_manifest.signed_files
	p := sf.path
	h := sf.sha256
}

deny contains decision if {
	some path, meta in input.bundle.files
	meta.replay_critical == true
	not signed_path_to_hash[path]
	decision := {
		"rule_id": "rule-4-replay-critical-files-must-be-signed",
		"message": sprintf(
			"replay-critical file %q not listed in signed_manifest.signed_files",
			[path],
		),
	}
}

deny contains decision if {
	some path, meta in input.bundle.files
	meta.replay_critical == true
	signed_path_to_hash[path]
	signed_path_to_hash[path] != meta.sha256
	decision := {
		"rule_id": "rule-4-replay-critical-files-must-be-signed",
		"message": sprintf(
			"replay-critical file %q hash in signed_manifest (%v) != hash in files (%v)",
			[path, signed_path_to_hash[path], meta.sha256],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-5: every provenance model_invocation MUST have an exactly-matching
#          replay invocation on (invocation_id, model_id, prompt sha, input
#          sha set, output sha set).
# ─────────────────────────────────────────────────────────────────────────────
replay_invocations contains inv if {
	some role in input.replay.roles
	some inv in role.invocations
}

deny contains decision if {
	some line in input.provenance
	line.action_type == "model_invocation"
	not invocation_matches_replay(line)
	decision := {
		"rule_id": "rule-5-provenance-replay-must-agree",
		"message": sprintf(
			"provenance model_invocation %q has no matching replay invocation",
			[line.invocation_id],
		),
	}
}

invocation_matches_replay(line) if {
	some inv in replay_invocations
	inv.invocation_id == line.invocation_id
	inv.model.model_id == line.model.model_id
	inv.prompt.sha256 == line.prompt_sha256
	sha_set_from_refs(inv.inputs) == sha_set_from_list(line.input_sha256s)
	sha_set_from_refs(inv.outputs) == sha_set_from_list(line.output_sha256s)
}

sha_set_from_refs(refs) := s if {
	s := {r.sha256 | some r in refs}
}

sha_set_from_list(lst) := s if {
	s := {h | some h in lst}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-6: auto-merge requires build.json present (Builder must have run)
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	not input.build
	decision := {
		"rule_id": "rule-6-auto-merge-requires-builder-output",
		"message": "auto-merge requires build.json; Builder has not run for this bundle",
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-7: auto-merge requires build.dispatch_outcome == "ok"
#         OR (auto_merge_evidence_path=reviewer-attested AND
#             dispatch_outcome=refused-no-reproducer).
#
# Per SPEC §5, the cross-family witness for auto-merge is EITHER a
# working Reproducer OR an accepting Reviewer. The reviewer-attested
# path is for bundles whose CVE class doesn't admit a sandbox
# reproducer (silent crash, network-bound, etc.) — Builder correctly
# emits refused-no-reproducer, and Steward accepts that outcome
# when the bundle has explicitly opted into the reviewer-attested
# path (rule 13 enforces the supporting artifacts).
#
# Bundles whose auto_merge_evidence_path is absent default to
# "reproducer", preserving v0.2.x behaviour (strict dispatch_outcome=ok).
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.build
	input.build.dispatch_outcome != "ok"
	# When reviewer-attested, refused-no-reproducer is the expected outcome.
	not _reviewer_attested_refused_no_reproducer_ok
	decision := {
		"rule_id": "rule-7-auto-merge-requires-builder-dispatch-ok",
		"message": sprintf(
			"auto-merge requires build.dispatch_outcome=ok; got %q",
			[input.build.dispatch_outcome],
		),
	}
}

_reviewer_attested_refused_no_reproducer_ok if {
	input.bundle.auto_merge_evidence_path == "reviewer-attested"
	input.build.dispatch_outcome == "refused-no-reproducer"
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-8: auto-merge requires build.patched_build.outcome == "succeeded"
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.build
	input.build.patched_build.outcome != "succeeded"
	decision := {
		"rule_id": "rule-8-auto-merge-requires-patched-build-succeeded",
		"message": sprintf(
			"auto-merge requires build.patched_build.outcome=succeeded; got %q",
			[input.build.patched_build.outcome],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-9: auto-merge forbidden on proxy reproducer
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.repro_scoring
	some scorer in input.repro_scoring.scorers
	scorer.scorer_name == "repro-schema-valid"
	scorer.details.is_proxy == true
	decision := {
		"rule_id": "rule-9-auto-merge-forbidden-on-proxy-reproducer",
		"message": "auto-merge forbidden when reproducer declares meta.proxy=true; bundle.kind must be human-review-required",
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-10: auto-merge requires both load-bearing reproducer scorers at 1.0
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.repro_scoring
	some scorer in input.repro_scoring.scorers
	scorer.scorer_name == "repro-unpatched-fails"
	scorer.applies == true
	scorer.score < 1.0
	decision := {
		"rule_id": "rule-10-auto-merge-requires-repro-unpatched-fails",
		"message": sprintf(
			"auto-merge requires repro-unpatched-fails=1.0 (or proxy reproducer, gated by rule-9); got score=%v",
			[scorer.score],
		),
	}
}

deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.repro_scoring
	some scorer in input.repro_scoring.scorers
	scorer.scorer_name == "repro-patched-passes"
	scorer.applies == true
	scorer.score < 1.0
	decision := {
		"rule_id": "rule-10-auto-merge-requires-repro-patched-passes",
		"message": sprintf(
			"auto-merge requires repro-patched-passes=1.0; got score=%v",
			[scorer.score],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-11: auto-merge requires Reviewer verdict == "accept"
#          (only applies when review-scoring-report.json is present)
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.review_scoring
	some scorer in input.review_scoring.scorers
	scorer.scorer_name == "review-schema-valid"
	scorer.details.verdict != "accept"
	decision := {
		"rule_id": "rule-11-auto-merge-requires-reviewer-accept",
		"message": sprintf(
			"auto-merge requires Reviewer verdict=accept; got %q",
			[scorer.details.verdict],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-12: auto-merge requires build.json produced on x86_64-linux
#
# nixpkgs's canonical CI platform is x86_64-linux. Bundles whose
# Reproducer signals were only validated on darwin-aarch64 (or any
# non-linux platform) carry the risk that the same PoC won't trigger
# the bug on Linux — see docs/DECISIONS.md (2026-05-12 "Linux Builder
# infrastructure proven (libtiff cert); two corpus-expansion findings"),
# specifically Finding 2 on the libtiff CVE-2024-13978 PoC. Requiring
# build.json.host.system == "x86_64-linux" forces the Reproducer-runs
# to have been exercised on the canonical platform before the bundle
# can claim auto-merge eligibility.
#
# Darwin-side reproduction remains valuable for development + initial
# validation; this rule just says "auto-merge needs the Linux pass."
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.build
	input.build.host.system != "x86_64-linux"
	decision := {
		"rule_id": "rule-12-auto-merge-requires-linux-build",
		"message": sprintf(
			"auto-merge requires build.json.host.system=x86_64-linux (nixpkgs CI canonical platform); got %q",
			[input.build.host.system],
		),
	}
}

# ─────────────────────────────────────────────────────────────────────────────
# rule-13: reviewer-attested auto-merge requires supporting artifacts.
#
# When bundle.auto_merge_evidence_path == "reviewer-attested", the
# cross-family witness for auto-merge is the Reviewer (per SPEC §5), not
# the Reproducer. Steward therefore requires:
#
#   (a) reproducer-refusal.json must be present in the bundle — a
#       machine-readable justification of why no Reproducer is feasible
#       for this CVE class (silent crash, sandbox-incompatible network,
#       recursion class, etc.). Without it, "reviewer-attested" is just
#       "we skipped the Reproducer" — Steward needs the why on the wire.
#
#   (b) review-scoring-report.json must be present with verdict=accept.
#       Rule 11 already enforces accept when review_scoring is present,
#       but only when it's present — for reviewer-attested it MUST be
#       present, because the Reviewer is now the load-bearing witness.
#
# Bundles with auto_merge_evidence_path=reproducer (the default) are
# unaffected — rule 7 / 9 / 10 carry the Reproducer evidence path.
# ─────────────────────────────────────────────────────────────────────────────
deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.bundle.auto_merge_evidence_path == "reviewer-attested"
	not input.reproducer_refusal
	decision := {
		"rule_id": "rule-13-reviewer-attested-requires-reproducer-refusal",
		"message": "auto_merge_evidence_path=reviewer-attested requires reproducer-refusal.json documenting why no Reproducer is feasible",
	}
}

deny contains decision if {
	input.bundle.kind == "auto-merge"
	input.bundle.auto_merge_evidence_path == "reviewer-attested"
	not input.review_scoring
	decision := {
		"rule_id": "rule-13-reviewer-attested-requires-reviewer-accept",
		"message": "auto_merge_evidence_path=reviewer-attested requires review-scoring-report.json with verdict=accept",
	}
}
