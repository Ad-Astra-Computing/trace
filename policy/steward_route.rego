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

# ─── auto-merge-eligible: resolver eligible AND every affected high-conf ────

state := "auto-merge-eligible" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	count(input.finding.affected) > 0
	every a in input.finding.affected {
		a.confidence == "high"
	}
}

_all_reasons contains "eligible-high-confidence" if {
	input.upstream_ref
	input.upstream_ref.eligibility.verdict == "eligible"
	input.finding
	count(input.finding.affected) > 0
	every a in input.finding.affected {
		a.confidence == "high"
	}
}

# ─── helpers ────────────────────────────────────────────────────────────────

_strip_prefix(s, prefix) := suffix if {
	startswith(s, prefix)
	suffix := substring(s, count(prefix), -1)
}
