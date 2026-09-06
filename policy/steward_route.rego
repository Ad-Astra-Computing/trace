# Steward routing policy. Classifies a Scout inbox entry into one of
# four states with machine-readable reason codes. This runs BEFORE a
# bundle is assembled; the existing trace.steward package handles
# the pre-merge gate against fully-built bundles.
#
# Input shape (built by agents/steward/agent.py):
#   input.finding         contents of finding.json (optional;
#                         absent when finding_status == mapping-failure)
#   input.upstream_ref    contents of upstream-ref.json (optional;
#                         absent when finding_status == mapping-failure)
#   input.mapping_failure contents of mapping-failure.json (optional)
#
# Output keys:
#   data.trace.steward.route.state         one of:
#                                            "auto-merge-eligible"
#                                            "human-review-required"
#                                            "advisory-only"
#                                            "reject"
#   data.trace.steward.route.reason_codes  list[str], stable code prefixes
#                                          callers can group on for metrics

package trace.steward.route

import rego.v1

default state := "reject"

reason_codes contains code if some code in _all_reasons

# ─── reject: no actionable input ────────────────────────────────────────────

state := "reject" if {
	not input.finding
	not input.mapping_failure
}

_all_reasons contains "no-actionable-input" if {
	not input.finding
	not input.mapping_failure
}

# ─── reject: mapping failed (Scout couldn't connect CVE to nixpkgs attr) ────

state := "reject" if {
	input.mapping_failure
	not input.finding
}

_all_reasons contains "mapping-failure" if {
	input.mapping_failure
	not input.finding
}

# ─── advisory-only: finding exists, but resolver says no upstream fix ───────

state := "advisory-only" if {
	input.upstream_ref
	startswith(input.upstream_ref.eligibility.verdict, "ineligible-")
}

_all_reasons contains code if {
	input.upstream_ref
	startswith(input.upstream_ref.eligibility.verdict, "ineligible-")
	code := sprintf("upstream-ref-ineligible:%s", [
		_strip_prefix(input.upstream_ref.eligibility.verdict, "ineligible-"),
	])
}

# ─── human-review-required: resolver routes to review ───────────────────────

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible-requires-human-review"
}

_all_reasons contains code if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible-requires-human-review"
	code := sprintf("upstream-ref-requires-human-review:%s", [
		input.upstream_ref.eligibility.human_review_trigger,
	])
}

# ─── human-review-required: impact analysis incomplete ────────────────────
#     (Cartographer can run with a minimal graph backend that does not
#      compute reverse-closure; in that case impact.analysis_status is
#      not 'complete' and we MUST route to review until a real graph
#      adapter lands. See agents/cartographer/snapshot_graph.py.)

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.impact
	not _impact_analysis_complete
}

_all_reasons contains code if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.impact
	not _impact_analysis_complete
	code := sprintf("impact-unanalyzed:%s", [object.get(input.impact, "analysis_status", "absent")])
}

# Fail closed on a MISSING analysis_status. `analysis_status != "complete"` is
# undefined when the field is absent, so an impact.json that simply omits it used
# to slip past this gate and stay auto-merge eligible. The field is optional in
# impact-schema.json, so absence is reachable, and absence means nobody asserted
# the reverse-closure analysis ran.
_impact_analysis_complete if {
	input.impact.analysis_status == "complete"
}

# ─── human-review-required: confidence below high blocks auto-merge ─────────
#     (echoes rule-1 of the merge-gate policy at routing time)

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	some a in input.finding.affected
	a.confidence != "high"
}

_all_reasons contains code if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	some a in input.finding.affected
	a.confidence != "high"
	code := sprintf("confidence-not-high:%s", [a.confidence])
}

# ─── human-review-required: patcher not ready (no grounded hash) ────────────
#     Even with verdict=eligible + high-confidence affected, the Patcher
#     prompt's rule 8 refuses unless a sha256 the patch would need to
#     update is grounded by an entry in upstream_ref.prefetch_hashes[].
#     A pre-flight gate here is more honest than letting Patcher refuse
#     downstream: an inbox entry that lacks prefetch material is NOT
#     patcher-ready, regardless of resolver verdict.
#
#     Three blocking cases, all routed to human-review-required:
#       (a) prefetch_hashes absent or empty
#       (b) at least one prefetch_skips[] entry with required_for_patch
#       (c) at least one prefetch_failures[] entry with required_for_patch

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	not _has_prefetch_hashes
}

_all_reasons contains "patcher-not-ready:missing-prefetch-hashes" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	not _has_prefetch_hashes
}

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	some s in input.upstream_ref.prefetch_skips
	s.required_for_patch == true
}

_all_reasons contains code if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	some s in input.upstream_ref.prefetch_skips
	s.required_for_patch == true
	code := sprintf("patcher-not-ready:prefetch-skipped:%s", [s.name])
}

state := "human-review-required" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	some f in input.upstream_ref.prefetch_failures
	f.required_for_patch == true
}

_all_reasons contains code if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	some f in input.upstream_ref.prefetch_failures
	f.required_for_patch == true
	code := sprintf("patcher-not-ready:prefetch-failed:%s", [f.name])
}

# ─── auto-merge-eligible: resolver eligible AND every affected high-conf ────
#     AND patcher-ready (prefetch material present and not blocked)

state := "auto-merge-eligible" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	count(input.finding.affected) > 0
	every a in input.finding.affected {
		a.confidence == "high"
	}
	not _impact_unanalyzed
	_has_prefetch_hashes
	not _prefetch_blocked
}

_all_reasons contains "eligible-high-confidence" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	count(input.finding.affected) > 0
	every a in input.finding.affected {
		a.confidence == "high"
	}
	not _impact_unanalyzed
	_has_prefetch_hashes
	not _prefetch_blocked
}

_impact_unanalyzed if {
	input.impact
	not _impact_analysis_complete
}

_has_prefetch_hashes if {
	input.upstream_ref.prefetch_hashes
	count(input.upstream_ref.prefetch_hashes) > 0
}

_prefetch_blocked if {
	some s in input.upstream_ref.prefetch_skips
	s.required_for_patch == true
}

_prefetch_blocked if {
	some f in input.upstream_ref.prefetch_failures
	f.required_for_patch == true
}

# ─── helpers ────────────────────────────────────────────────────────────────

_strip_prefix(s, prefix) := suffix if {
	startswith(s, prefix)
	suffix := substring(s, count(prefix), -1)
}
