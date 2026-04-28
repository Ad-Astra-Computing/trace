# Probe: claude-sonnet-4-6 as patcher across the v0 inner-loop cohort

**Date:** 2026-04-28
**Prompt:** `prompts/patcher.v1.md` (sha `06272c462ac0e39befcdeef6565b80b1007b925ad5ae0fa11042baa1a6d2e322`, identical to baseline)
**Reviewer:** unchanged (out of scope for this probe)
**Question:** Does the patcher.v1 contract remain strong when the patcher model changes, or is the current success mostly Opus-specific?

## Cohort

Six dispatchable inner-loop bundles, all with a `claude-opus-4-7` baseline at `composite_merge_ready_rate = 1.000`:

- `CVE-2024-49195--mbedtls`
- `CVE-2025-13878--bind`
- `CVE-2025-67899--uriparser`
- `CVE-2025-9230--openssl_3`
- `CVE-2026-25949--traefik`
- `CVE-2025-4598--systemd`

Probe ran each bundle through the patcher executor with `--model claude-sonnet-4-6`, scored via `tests/fixtures/real-ci/score_invocation.py`, then aggregated under cohort label `real-second-model-probe-sonnet`.

## Result

| Metric | claude-opus-4-7 (baseline) | claude-sonnet-4-6 (probe) |
|---|---|---|
| Attempts | 6 | 6 |
| Parser refusals | 0 | **1** |
| Patches parsed | 6 | 5 |
| At threshold ≥ 0.95 | 6 | 0 |
| **patch_rate** | **1.000** | **0.000** |
| **merge-ready rate mean** | **1.000** | **0.800** |
| schema-valid (`git apply --check`) | 1.000 | **0.000** |
| upstream-ref-compliance | 1.000 | 1.000 |
| hash-verifiability | 1.000 | 1.000 |
| unrelated-file-touch-rate | 1.000 | 1.000 |
| minimality | 1.000 | 1.000 |

Substantive scorers all 1.000 across both models. Mechanical scorer (schema-valid) drops to 0.000 under sonnet. Sonnet engages the contract correctly on every non-mechanical axis but produces patches that don't apply.

## Three distinct failure modes, all caught by the existing pipeline

### 1 / 6 — parser refusal

- **systemd:** sonnet emitted 1631 chars of prose preamble before the `=== BEGIN` marker. `PatcherOutputMalformed` raised at the runner's parse-before-write boundary; no corrupt files written. The strict-output prompt contract is a real load-bearing guard against sonnet-family verbosity on long-context tasks.

### 2 / 6 — real-nixpkgs path emission

- **bind:** sonnet wrote `--- a/pkgs/by-name/bi/bind/package.nix` instead of `--- a/package.nix`.
- **uriparser:** sonnet wrote `--- a/pkgs/by-name/ur/uriparser/package.nix` instead of `--- a/package.nix`.

Sonnet appears to "helpfully reconstruct" the canonical nixpkgs layout, defeating the bundle-isolation contract. Opus used the bundle-relative `package.nix` path on every run.

### 3 / 6 — wrong unified-diff hunk-header line counts

- **traefik, mbedtls, openssl_3:** correct path (`--- a/package.nix`) but wrong `@@ -X,Y +X,Y @@` ranges. Example: traefik's `@@ -10,11 +10,11 @@` claims 11-line hunks but the body holds a different count. `git apply --check` strict-rejects.

Opus's hunk headers were exact every time.

## Conclusion

- **Patcher-not-viable** for claude-sonnet-4-6 under the v0 contract. Three independent mechanical failure modes across five out of six attempts, plus one parser refusal on the largest task.
- **Reviewer-viable** confirmed elsewhere — sonnet's prior reviewer runs scored 16/16 evidence-cited and produced substantive accept/reject calls. The model is not weaker overall; it is structurally weaker at producing exact unified-diff output.
- **Contract portability** is therefore conditional: substantive axes (citations, grounded hashes, minimality, file scope) are model-portable; mechanical axes (output-shape strictness, exact path naming, unified-diff arithmetic) are not.

The patcher.v1 prompt is **not** changed in response to this probe. Tightening the prompt to accommodate a weaker model risks regressing the working model. Any prompt iteration to lift sonnet's mechanical performance is a separate, A/B-gated experiment.

## Decision

`claude-opus-4-7` is locked as the v0 patcher model. `claude-sonnet-4-6` is not qualified as patcher; it remains a qualified reviewer candidate.

See `docs/DECISIONS.md` for the project-level entry.

## Artifacts

Per-bundle outputs are in `/tmp/sonnet-probe/<bundle>/` (ephemeral; not committed). Re-running the probe is deterministic-modulo-model-sampling: stage copies of the six bundles into a writeable root, strip patcher invocations from each replay.json, run `trace replay <bundle> --role patcher --model claude-sonnet-4-6 --execute --traces-root <staged-root>`, score, aggregate via `trace eval patch-rate --cohort real-second-model-probe-sonnet --reports '<staged-root>/**/scoring-report.json'`.
