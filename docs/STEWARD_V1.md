# Steward v1 — contract specification

**Status:** locked. This document defines the v1 Steward gate: which rules fire, what input each rule reads, and which `bundle.kind` value each rule constrains. The Rego rules in `policy/steward.rego` are derived from this spec.

**Supersedes:** SPEC.md §1.2 names Steward ("opa-rule-driven merge gate"). v0 had five rules covering bundle/finding/upstream-ref/replay/provenance. This document extends the rule set with six new rules consuming the artifacts produced by Reproducer + Builder + Reviewer (which all landed structurally on 2026-04-28).

**Related decisions:**
- `docs/REPRODUCER_V1.md` §7 — proxy bundles are NOT auto-merge eligible.
- `docs/BUILDER_V1.md` §7 — auto-merge requires `patched_build.outcome == "succeeded"`, both reproducer scorers at 1.0, `dispatch_outcome == "ok"`.
- 2026-04-27 (rev 1) — Reviewer verdict `reject` or `escalate` must forbid auto-merge.

---

## 0. Purpose

Steward answers exactly one question per bundle:

> *Given everything the upstream pipeline has produced (Patcher diff + rationale, Reproducer artifacts + scoring, Reviewer verdict + scoring, Builder verdict), should this bundle auto-merge, go to human review, or ship as advisory-only?*

Steward is **deterministic policy**. No LLM. Every decision is keyed to a stable `rule_id`, surfaces a structured `message`, and is auditable from the bundle's on-disk state alone.

The output is a single decision: `allow: bool` plus `deny: Set[{rule_id, message}]`. `allow == true` iff `deny` is empty. The CLI / CI surfaces the decision; humans read the deny set when the gate fails.

---

## 1. Input shape

Steward's input is the union of bundle artifacts:

```jsonc
{
  "bundle":         <bundle.json>,
  "finding":        <finding.json>,
  "upstream_ref":   <upstream-ref.json>,
  "replay":         <replay.json>,
  "provenance":     [<provenance.jsonl line>, ...],
  "build":          <build.json or null>,
  "repro_scoring":  <repro-scoring-report.json or null>,
  "review_scoring": <review-scoring-report.json or null>,
  "review":         <parsed review.md as a struct, or null>
}
```

Each field is loaded by the test runner / CI invocation and passed to opa as a single JSON document. Missing files map to `null`; rules check for presence before traversal.

---

## 2. Rule set

### v0 rules (preserved unchanged from `policy/steward.rego` as of `b2b3b2c` baseline)

| rule | summary | input |
|---|---|---|
| **rule-1** | auto-merge requires every affected derivation to have `confidence == "high"` | `bundle`, `finding` |
| **rule-2** | auto-merge forbidden when `upstream_ref.eligibility.verdict == "eligible-requires-human-review"` | `bundle`, `upstream_ref` |
| **rule-3** | auto-merge requires `replay.cross_family_rule_honored == true` | `bundle`, `replay` |
| **rule-4** | every replay-critical file MUST appear in `bundle.signed_manifest.signed_files` with a matching sha256 | `bundle` |
| **rule-5** | every provenance `model_invocation` MUST have an exactly-matching replay invocation | `replay`, `provenance` |

### v1 additions

| rule | summary | input |
|---|---|---|
| **rule-6** | auto-merge requires `build.json` present | `bundle`, `build` |
| **rule-7** | auto-merge requires `build.dispatch_outcome == "ok"` | `bundle`, `build` |
| **rule-8** | auto-merge requires `build.patched_build.outcome == "succeeded"` | `bundle`, `build` |
| **rule-9** | auto-merge forbidden when reproducer is proxy (`build.unpatched.applied == false` AND repro-scoring marks `is_proxy == true`) | `bundle`, `build`, `repro_scoring` |
| **rule-10** | auto-merge requires `repro-unpatched-fails == 1.0` (when applicable) AND `repro-patched-passes == 1.0` | `bundle`, `repro_scoring` |
| **rule-11** | auto-merge requires reviewer verdict `accept` when `review-scoring-report.json` is present | `bundle`, `review_scoring` |

Total: 11 rules. Each is `bundle.kind == "auto-merge"`-guarded — non-auto-merge bundles are not constrained by these rules and pass Steward unconditionally on the chain rules (rules 1-3, 6-11). Rules 4 and 5 apply to ALL kinds because replay integrity and signed-manifest correctness are universal v0 requirements.

---

## 3. Per-rule semantics

### rule-1 — auto-merge requires high confidence (preserved)

```
deny if
  bundle.kind == "auto-merge"
  AND some affected_attr in finding.affected
  AND affected_attr.confidence != "high"
```

Rationale: low- or medium-confidence CPE/PURL mappings can mis-attribute a CVE; auto-merge would silently propagate the misattribution. Surfaces in `CVE-0000-9004--low-confidence-auto-merge` fixture.

### rule-2 — auto-merge forbidden on eligible-requires-human-review (preserved)

```
deny if
  bundle.kind == "auto-merge"
  AND upstream_ref.eligibility.verdict == "eligible-requires-human-review"
```

Rationale: bundle.kind and upstream-ref verdict can disagree at the schema layer; Steward catches the cross-field inconsistency. Surfaces in `CVE-0000-9006--major-jump-auto-merge` fixture.

### rule-3 — auto-merge requires cross-family rule honored (preserved)

```
deny if
  bundle.kind == "auto-merge"
  AND replay.cross_family_rule_honored == false
```

Rationale: same-family Patcher/Reviewer (or now Patcher/Reproducer) pairs lose adversarial signal. Surfaces in `CVE-0000-9005--same-family-pair-not-flagged` fixture.

### rule-4 — replay-critical files must be signed (preserved)

```
deny if
  some path, meta in bundle.files
  AND meta.replay_critical == true
  AND (path NOT in signed_manifest.signed_files
       OR signed_manifest.signed_files[path].sha256 != meta.sha256)
```

Rationale: any replay-critical file outside the signed manifest defeats the bundle's tamper-evidence. Surfaces in `CVE-0000-9007--unsigned-replay-critical-file` fixture.

### rule-5 — provenance/replay must agree (preserved)

```
deny if
  some line in provenance
  AND line.action_type == "model_invocation"
  AND no matching replay invocation on (invocation_id, model_id, prompt_sha,
                                         input sha set, output sha set)
```

Rationale: provenance line and replay invocation must cross-reference. Mismatch is evidence of post-hoc tampering. Surfaces in `CVE-0000-9003--replay-provenance-mismatch` fixture.

### rule-6 — auto-merge requires build.json present (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND build is null
```

Rationale: per `docs/BUILDER_V1.md` §7, auto-merge cannot proceed without Builder having executed. Pre-Builder bundles are by definition not auto-merge eligible.

### rule-7 — auto-merge requires Builder dispatch_outcome == "ok" (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND build is non-null
  AND build.dispatch_outcome != "ok"
```

Rationale: Builder records its own dispatch result. `refused-no-patch`, `refused-no-reproducer`, `patch-apply-failed`, and `infra-failure` all preclude auto-merge by definition.

### rule-8 — auto-merge requires patched_build succeeded (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND build is non-null
  AND build.patched_build.outcome != "succeeded"
```

Rationale: a patch that doesn't even build cannot be auto-merged. Independent of reproducer evidence — a non-buildable patch is an immediate reject.

### rule-9 — auto-merge forbidden on proxy reproducer (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND repro_scoring is non-null
  AND any scorer in repro_scoring.scorers has:
        scorer_name == "repro-schema-valid"
        AND details.is_proxy == true
```

Rationale: per `docs/REPRODUCER_V1.md` §7, proxy bundles automatically downgrade to `human-review-required` with `kind_reason: reproducer-is-proxy`. A bundle declaring `kind=auto-merge` with a proxy reproducer is internally inconsistent.

### rule-10 — auto-merge requires both reproducer scorers at 1.0 (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND repro_scoring is non-null
  AND (repro-unpatched-fails applies AND its score < 1.0)
       OR (repro-patched-passes applies AND its score < 1.0)
```

Rationale: the load-bearing pair from `docs/REPRODUCER_V1.md` §9. Both must score 1.0 in non-proxy bundles. The `applies` guard preserves rule-9's proxy semantics — proxy bundles are denied via rule-9, not rule-10.

### rule-11 — auto-merge requires reviewer verdict accept (NEW)

```
deny if
  bundle.kind == "auto-merge"
  AND review_scoring is non-null
  AND any scorer in review_scoring.scorers has:
        scorer_name == "review-schema-valid"
        AND details.verdict in {"reject", "escalate"}
```

Rationale: a Reviewer that explicitly says reject or escalate cannot be over-ridden by auto-merge. The Reviewer's verdict is binding; only `accept` allows auto-merge.

---

## 4. What Steward does NOT enforce

Out of scope for v1; explicitly NOT rule-shaped:

- **Substantive correctness of the patch.** Steward does not re-derive whether the patch is the "right" fix. That's the Reviewer's job.
- **Reviewer-Steward disagreement signal interpretation.** The `review-disagreement` scorer (advisory) records whether the Reviewer's verdict diverged from a Steward-derived auto-merge signal; Steward does not consume the disagreement scorer in its gate. That feedback loop would be circular.
- **Cross-CVE bundle merging.** Steward decides one bundle at a time. Multi-bundle policy lives elsewhere.
- **CVE-class-specific waivers.** No "if CVE matches pattern X, allow despite rule Y." Waivers belong in the human-review queue, not in deterministic policy.

---

## 5. Decision recording

The Steward decision is consumed by the GitHub Actions merge-gate workflow (`.github/workflows/steward.yml`, deferred). v1 records the decision into the bundle's `provenance.jsonl` as a `steward_decision` line:

```jsonc
{
  "ts": "...",
  "action_type": "steward_decision",
  "policy_version": "<sha256 of policy/steward.rego>",
  "input_sha256": "<sha256 of the canonicalised opa input doc>",
  "allow": true,
  "deny": []
}
```

The provenance line exists alongside the model_invocation lines so an auditor can replay the gate decision later. v0 does NOT yet write this line — that's left for the Steward CI integration arc.

---

## 6. Fixture coverage

The 14 fixtures under `traces/example/` cover every rule:

| rule | positive-allow fixture(s) | deny fixture(s) |
|---|---|---|
| rule-1 | mbedtls, bind, traefik, full-chain-auto-merge | low-confidence-auto-merge |
| rule-2 | systemd, uriparser, openssl_3 | major-jump-auto-merge |
| rule-3 | full-chain-auto-merge | same-family-pair-not-flagged |
| rule-4 | full-chain-auto-merge | unsigned-replay-critical-file |
| rule-5 | full-chain-auto-merge | replay-provenance-mismatch |
| rule-6 | full-chain-auto-merge | auto-merge-missing-builder |
| rule-7 | full-chain-auto-merge | auto-merge-builder-dispatch-failed |
| rule-8 | full-chain-auto-merge | auto-merge-patched-build-failed |
| rule-9 | full-chain-auto-merge | auto-merge-proxy-reproducer |
| rule-10 | full-chain-auto-merge | auto-merge-repro-signal-failed |
| rule-11 | full-chain-auto-merge | auto-merge-reviewer-rejected |

The pre-Builder cohort-1 fixtures (mbedtls, bind, traefik, patcher-fixture-dispatchable) are flipped to `steward_expected=invalid` with `steward_rule_id=rule-6-auto-merge-requires-builder-output` because they predate Builder and cannot satisfy the v1 contract. The new synthetic fixture `CVE-0000-0011--full-chain-auto-merge` is the v1 happy-path test case carrying all required artifacts.

---

## 7. Open questions parked

1. **Numeric thresholds for the load-bearing scorers.** rule-10 currently demands 1.0 exactly. A future v2 may relax to ≥ some configurable threshold (e.g. 0.95) to tolerate scorer noise. v1 keeps the strict 1.0 floor.
2. **Schema reconciliation.** The reviewer scoring report carries `verdict` inside `scorers[scorer_name=review-schema-valid].details.verdict`. The reproducer scoring report carries `is_proxy` similarly. v1 reads from the `details` block; if `agents/scorers/aggregator.py` ever surfaces these as top-level fields too, rule-9 / rule-11 will need to accept either location (or the scorer reports normalise to one).
3. **Steward rule versioning.** v1 locks 11 rules. Adding a rule-12 in a v2 cycle is allowed, but renaming or removing any of rules 1-11 requires a SPEC-level amendment per the trace project's append-only convention.
