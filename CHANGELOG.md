# Changelog

Append-only release notes. Tagged releases land at the top; unreleased work accumulates under a `Unreleased` heading until a tag cuts.

The decision log at [`docs/DECISIONS.md`](docs/DECISIONS.md) is the *why* and the running story; this file is the *what shipped*. They reference each other where useful but do not duplicate.

---

## Unreleased

### N=3 sandbox-positive corpus; Phase 2 harvest baseline; hash-verifiability scorer fix

**N=3 sandbox-positive corpus (git-lfs, assimp, expat).** Extends the sandbox-positive cert-green corpus from N=2 (git-lfs, assimp) to N=3 by adding expat CVE-2024-8176 (CWE-674 non-TCO stack overflow via linear entity chain). Clean 2.6.4→2.7.0 version-bump; blast-radius-exceeds-threshold route (~4291 reverse-closure deps). The N=3 cohort eval scores: Patcher `patch_rate=1.000` (3/3 at composite ≥0.95), Reviewer `accept_rate=1.000` / `evidence_cited_mean=1.000` / `attestation_correct_rate=0.667` (git-lfs pre-validator era) / `reviewer_steward_disagreement_rate=0.667` (assimp + expat blast-radius escalation — expected), Reproducer `repro_rate mean=0.667` (git-lfs 0.0 v4-era F13-pattern technical debt, assimp 1.0, expat 1.0). Expat cert run [26348784388](https://github.com/Ad-Astra-Computing/trace/actions/runs/26348784388) closed end-to-end green 2026-05-25 after F18 ulimit fix.

**Key finding — CWE-674 sub-class discriminator.** The TCO-distinguisher for CWE-674 recursion CVEs: if the recursive function maintains non-trivial per-frame state (return value propagation, accumulator, sub-expression tracking), gcc cannot tail-call-optimize it and the default stack will overflow reliably. Expat's `doContent` / `contentProcessor` carries XML parse state across frames — non-TCO. Contrast uriparser (F11) and libxml2 (same class, TCO'd at -O2). The new filter prevents future F11-class retirements on CWE-674 candidates.

**Phase 2 harvest: two new candidates in `eval/candidates.jsonl`.** CWE-191 integer underflow → stack buffer underwrite class (CVE-2025-47256, libxmp) and CWE-190 integer overflow → memcpy SIGSEGV class (CVE-2025-68431, libheif). libxmp staged (bundle bootstrapped, Patcher pending); libheif queued. COMPLEXITY NOTE for libxmp: nixpkgs 4.6.2→4.6.3 diff is a complete package rewrite (fetchurl → fetchFromGitHub, autotools → CMake/Ninja, LGPL 2.1+ → MIT), classified as `patch_shape=package-rewrite`. fetchFromGitHub hash manually pinned in upstream-ref.json (schema_version 1.1.0, source=manual-pinned).

**Hash-verifiability scorer false-positive fix (`agents/scorers/hash_verifiability.py`).** The silent-omission detection path incorrectly flagged hash attributes left unchanged across a version bump when the unchanged value was already grounded against the prefetch table (i.e., the module upgrade didn't change the vendored dependencies). Fixed by exempting any attribute whose current `package.nix` value appears in `prefetch_values` from the omission count. The git-lfs bundle (3.7.0→3.7.1, Go CVE fix, vendorHash legitimately unchanged) scored 0.9 composite before the fix; 1.0 composite after. Existing corpus-1 cohort tests (mbedtls, bind, traefik) unaffected.

**lrzip CVE-2025-15571 retired (F8b-concurrency).** Third F8 sub-class codified: CWE-476 CVEs where the upstream issue describes a concurrency race condition or mentions ASAN delays as required for reproduction are NOT reliably sandbox-positive at default optimization. The crash at `0x000000000080` (offset within freed struct, not address zero) requires `clear_rulist` to race against `ucompthread` — a race window that only ASAN's sleep-injection widens reliably. Pre-cert local probe was sufficient evidence; cert dispatch skipped. Patcher (opus) + Reviewer (sonnet) artifacts preserved as evidence of the patch chain.

**F18 — Nix build sandbox inherits unlimited stack from nix-daemon.** Discovered during expat cert (cert run 26323566165): in `pkgs.runCommand` scripts on the GHA ubuntu-latest runner with DeterminateSystems nix-installer, the process inherits `ulimit -s unlimited` from the nix-daemon. This causes stack-overflow CVEs whose reproducer depends on the standard 8MB Linux stack limit to not crash. Fix: explicitly set `ulimit -s 8192` in reproducer.nix `runCommand` scripts for CWE-121/CWE-674 bundles. The F18 fix is now a prompt-level lesson for the next Reproducer prompt version (v9 era).

**Corpus table: N=20 bundles.** SEED_INDEX updated to twenty entries.

---

## v0.4.0 — 17 May 2026

### F1–F7 contract slice on wget2: drop-only patches, per-side test, gated SIGNAL, pinned `pkgs`, pre-patch unpatched tree; wget2 retired as v0.1 anchor

v0.3.0 landed the v0 cohort split. v0.4.0 closes the v0 → v0.1 contract gap surfaced by trying to run a real model-attested + sandbox-positive bundle end-to-end. The wget2 bundle drove a six-cert arc that produced seven distinct structural findings (F1–F7); six closed at the contract / Builder / prompt layer, one (F6 — wget2's metalink CVE PoC requires HTTP) triggered retirement of wget2 as the v0.1 anchor with a codified anchor-selection filter to prevent the class from being picked again.

**F1 — Patcher drop-only relaxation (`policy/bundle-schema.json`, `traces/example/CVE-2025-69194--wget2/patch-drop-rationale.md`, DECISIONS 2026-05-17).** v0.3.0's Patcher contract was strictly "version + hash bump" on `package.nix`. When the upstream fix release obsoletes a downstream nixpkgs workaround patch (the wget2 `gettext-0.25.patch` case), `patched_build` fails at the obsolete patch's Hunk failure and the entire bundle stalls. v0.4.0 allows Patcher to drop a `patches = [...]` entry plus (optionally) delete the patch file, subject to: hunk-apply failure must be demonstrable; bundle must ship `patch-drop-rationale.md` explaining the drop is workaround-class not behaviour-class; Reviewer must attest. Refresh (rewriting a patch to apply at the new version) remains deferred to v0.2. The wget2 bundle's `patch.diff` now drops `gettext-0.25.patch`; nixpkgs master independently made the same drop, confirming the workaround was version-specific.

**F2, F3, F5 — reproducer prompt corrections (`prompts/reproducer.v3.md`).** Three prompt fixes landed in sequence on the wget2 arc:

* **F2 — per-side `passthru.test` shape.** Builder calls `(import reproducer.nix {}).unpatched.test` and `.patched.test` as two independent invocations; the prompt previously documented a shared top-level `test` attr that Builder couldn't locate. Now each side is a derivation with its own `passthru.test`.
* **F3 — gated SIGNAL emission.** Previously the prompt allowed `echo SIGNAL_<state>: ...` after a swallowed-failure invocation (`${binary} ... || true`). The test could "pass" with a false SIGNAL even when the binary errored on a wrong CLI flag and never exercised the affected code. v0.4.0 prompt requires: (1) invoke and capture stdout/stderr/exit code; (2) check preconditions (binary actually exercised the affected surface); (3) evaluate the discriminating predicate with positive evidence preferred over absence-checks; (4) SIGNAL line emitted ONLY inside the success branch, predicate-not-fired exits non-zero. The wget2 cert sequence empirically showed the contract refusing to mint a false SIGNAL — the framework's honesty guarantee.
* **F5 — wget2 metalink flag.** Worked example corrected from `--input-metalink=FILE` (unrecognised by wget2) to `--force-metalink -i FILE` (the actual flag, verified via `wget2 --help`).

**F4 — Builder `pkgs`-pin (`agents/builder/runner.py:_repro_nix_expression`).** Previously `<nixpkgs>` in `reproducer.nix` resolved against the system's NIX_PATH, which on Determinate Nix's CI image is some unspecified channel — usually not the bundle's pinned rev. `pkgs.wget2` was thus 2.2.1 from cache, the override produced a frankenversion (no `gettext-0.25.patch`), bootstrap collapsed. v0.4.0 has Builder invoke reproducer.nix as `(import <repro> { pkgs = import <nixpkgs-checkout> {}; })` whenever `nixpkgs_pin` is provided, deterministically binding `pkgs.<attr>` references to the bundle's pinned tree. Two unit tests cover the pin/unpin forms.

**F7 — Pre-patch tree for unpatched.test (`agents/builder/runner.py:run_builder` §2.2a/§2.2b/§2.3/§2.4).** F1's patch-drop made the post-patch tree no longer carry workaround patches that the *prior* version needed. Builder previously evaluated both unpatched.test and patched.test against the same (post-patch) tree; the unpatched 2.2.0 reconstruction now collapsed on autoreconf because the bootstrap-fixing patch had been dropped. v0.4.0 splits the reproducer-runs around `patch_apply`: unpatched.test against the pre-patch tree (so `pkgs.<attr>` carries the prior version's patches list), patched.test against the post-patch tree. When `patch_apply` subsequently fails, the unpatched_phase is preserved in build.json — the evidence isn't thrown away. `test_unpatched_test_runs_before_patch_apply` uses a real git checkout to verify the working-tree content seen by each BuildRunner call matches the expected pre/post-patch state.

**wget2 retirement as v0.1 anchor (`docs/CORPUS.md` § Sandbox-positive PoC suitability filter, `policy/bundle-schema.json` new `sandbox-poc-requires-network` enum value).** Cert 6 — the cleanest end-of-slice state — had `patched_build` succeed, both reproducer-side derivations build clean, both wget2 binaries run honestly against the metalink fixture, and both exit `PREDICATE FAILED` with no SIGNAL minted. F3's gating contract worked exactly as designed: the framework refused to fake a green result on a reproducer that didn't actually exercise the CVE. The remaining gap is wget2-PoC-specific: the metalink path-traversal CVE requires a fetchable URL, wget2 rejects `file://` and `data:` schemes, the Nix build sandbox is network-isolated. Bridging this would mean wget2-specific scaffolding in the prompt (local-HTTP responder pattern, parser-side stderr-grepping); neither belongs in v0.1 generic contract.

The wget2 bundle is reclassified to `kind=human-review-required` with the new `kind_reason=sandbox-poc-requires-network`, preserved as evidence of the contract layer working end-to-end (F1's `patch-drop-rationale.md`, F7-correct `reproducer.nix`, six `_*-run-archive/` directories documenting the slice arc). The corpus's anchor-selection filter is now codified to prevent network-shaped CVEs being selected for the v0.1 sandbox-positive anchor slot. A future v0.5 / v0.2-contract slice may pick up wget2 again with deliberate local-HTTP scaffolding as an opt-in pattern.

**v0.1 anchor-selection filter (`docs/CORPUS.md` § Sandbox-positive PoC suitability filter).** New corpus rule for choosing future sandbox-positive anchors. A candidate qualifies iff its PoC: (1) triggers via local-file content + binary invocation only; (2) has no external network dependency; (3) has no daemon / listener requirement. Qualifying classes: parser crashes on malformed file input, integer-overflow on crafted numeric input, syscall-level boundary violations, memory-safety classes triggered by file-based fuzz, path-traversal where the binary writes from input directly (not via fetch). Disqualifying: HTTP-client CVEs, DNS-resolution CVEs, network-protocol parsers consuming network data, server-side CVEs. Pre-filters at harvest time, doesn't retrofit reproducer-specific scaffolding after the fact.

**Test suite.** 1039 passed, 29 skipped — up from 1030 on v0.3.0. Nine new tests: two for `_repro_nix_expression` pin/unpin forms (F4), one for `test_unpatched_test_runs_before_patch_apply` exercising the pre-patch evaluation guarantee with a real git checkout (F7), and assertion updates across the FakeBuildRunner-sequenced tests in `test_runner.py` + `test_mruby_asan_pipeline.py` for the new call order (unpatched, patched_build, patched).

---

## v0.3.0 — 14 May 2026

### Builder lands; Steward rules 6-13; reviewer-attested auto-merge path; v0 cohort split made explicit

v0.2.0 brought Scout online. v0.3.0 closes the loop on the other end of the chain: Builder runs against pinned nixpkgs for real, Steward gates auto-merge on Builder's evidence (rules 6-13), and the second cross-family witness (SPEC §5 reviewer-attested) is implemented in policy with synthetic anchors. The arc ends with the corpus's structural bifurcation surfaced honestly: the model-attested cohort (version-bump/mixed patch shapes) flows through reviewer-attested; the sandbox-positive cohort (overlay patch shapes) stays deterministic-no-model for v0. The split is documented as a design state, not papered over.

**Per-bundle Linux cert workflow.** `.github/workflows/bundle-linux-cert.yml` is a manual-dispatch (`workflow_dispatch`) workflow that takes a bundle directory name as input, reads `nixpkgs_rev` from `bundle.json`, fetches that revision, runs Builder against it on `ubuntu-latest`, verifies build.json shape (dispatch_outcome, patch_apply.applied, patched_build.outcome, host.system=x86_64-linux), greps SIGNAL substrings out of `reproducer-log.txt` (when present), and runs Steward via `opa eval`. Artifacts uploaded for diagnosability on any failure. Parameterised over bundle name so adding bundles needs no workflow edits. First successful dispatch: mruby cert sequence (May 11–12 2026); first auto-merge-eligible bundle to clear all 12 rules end-to-end on Linux remains pending.

**Builder ASAN instrumentation contract (slice 3a).** Bundles can opt into AddressSanitizer-instrumented unpatched/patched runs via a sibling `reproducer-instrumentation.json` document (`policy/reproducer-instrumentation-schema.json`). Builder threads `enable_sanitizer: true` and `asan` toolchain hints through `nix-build`; runner verifies the linker actually pulled in libasan before emitting `instrumentation: "asan"` on `build.json`. mruby ships the first real ASAN reproducer.nix (Darwin-validated; Linux ASAN cc-wrapper integration is the open blocker — slice closed as contract-proven 12 May 2026 with the blocker tracked separately).

**`disable_doCheck` knob.** Same instrumentation schema gains a `disable_doCheck` field. Builder wraps the patched-build sanity phase as `pkgs.<attr>.overrideAttrs (_: { doCheck = false; })` when set. Carved out of libtiff slice E: libtiff's check phase exceeds GHA's 60-minute job timeout even on a 6-hour `bundle-linux-cert` workflow, while the underlying derivation is fine. The escape hatch is per-bundle and explicit; default behaviour unchanged.

**dispatch_outcome contract.** New enum on `build.json`: `ok`, `refused-no-patch`, `refused-no-reproducer`, `patch-apply-failed`, `infra-failure`, `instrumentation-malformed`. Steward gates on the specific outcome (rule 7) so failures route to the right human-review reason rather than blanket-denying.

**Steward rules 6-13.** v0.2.0's Steward had five rules. v0.3.0 lands the auto-merge gate completely:
* **rule-6** — auto-merge requires `build.json` present (Builder must have run).
* **rule-7** — auto-merge requires `build.dispatch_outcome=ok`, with the reviewer-attested escape clause (`refused-no-reproducer` accepted when `bundle.auto_merge_evidence_path=reviewer-attested`).
* **rule-8** — auto-merge requires `build.patched_build.outcome=succeeded`.
* **rule-9** — auto-merge forbidden on proxy reproducer (`is_proxy=true`).
* **rule-10** — auto-merge requires both load-bearing reproducer scorers at 1.0 (`repro-unpatched-fails`, `repro-patched-passes`).
* **rule-11** — auto-merge requires Reviewer verdict=accept when `review-scoring-report.json` is present.
* **rule-12** — auto-merge requires `build.host.system=x86_64-linux` (nixpkgs CI canonical platform).
* **rule-13** — reviewer-attested bundles must ship `reproducer-refusal.json` AND `review-scoring-report.json` with verdict=accept.

Each rule has a deny-path fixture under `traces/example/CVE-0000-001N--*`.

**SPEC §5 reviewer-attested auto-merge path (slice C).** Bundles whose CVE class doesn't admit a sandbox Reproducer can carry the cross-family witness via Reviewer instead. New `bundle.auto_merge_evidence_path ∈ {reproducer, reviewer-attested}` field on `bundle.json` (default `reproducer`); when `reviewer-attested`, the schema requires `review.md` (not `review-refusal.json`) and rule-13 enforces the supporting artifacts. Two synthetic fixtures anchor the path: `CVE-0000-0019` (allow) and `CVE-0000-0020` (rule-13 deny when `reproducer-refusal.json` is absent).

**`patch_shape` axis on candidate + corpus rows.** Seventh SPEC §5a classification axis: `overlay | version-bump | hash-bump | mixed | unknown`. Determines whether a sandbox-positive Reproducer is feasible. `overlay` shapes (`patches += [./CVE-NNNN.patch]`, cherry-picked commits applied as patches) allow reconstructing the unpatched derivation by filtering the overlay out (the libtiff template). `version-bump` / `hash-bump` shapes change `pkgs.<attr>.src` to a new tagged archive; reconstructing unpatched needs a network fetcher, which the Reproducer parser forbids. All 51 candidate rows and 51 corpus entries backfilled. Distribution: version-bump 38, overlay 11, mixed 1, unknown 1.

**v0 corpus is bifurcated (and that's the v0 answer).** Cross-referencing the `patch_shape=overlay` shortlist against UpstreamRefResolver: every overlay candidate in the current corpus lacks a release tag containing the fix, so the resolver routes them to `ineligible-cherry-pick-required` → advisory-only → Reproducer rule 2 refuses. The model-attested cohort (39/51) flows through reviewer-attested; the sandbox-positive cohort (11/51) stays deterministic-no-model. No corpus candidate hits both paths under v0 rules. Documented as the v0 design state in `docs/CORPUS.md` (new section "v0 cohort split") with explicit curation filters for future harvesting. Two unification paths are recorded as v0.1 design branches: relax the resolver to allow overlay-via-fetchpatch when a release tag exists, OR carve out hash-pinned FOD lookup in the Reproducer parser for unpatched-src reconstruction. Neither shipped in v0.3.0.

**`fetchzip` prefetch bug fix.** The earlier `agents/upstream_ref_resolver/fetchzip_prefetch.py:_build_expression` shape (`old.src.overrideAttrs (_: { outputHash = fakeHash; })`) was unsound: `old.src` was already evaluated against the package's ORIGINAL version via `rec` binding, so `tag = "v${version}"` resolved at definition time to `"v<old>"`. Setting outputHash re-triggered FOD evaluation with the SAME URL → prefetch reported the OLD version's hash labelled as the NEW version. Caught by claude-sonnet-4-5 Reviewer on wget2 (real cross-family value — same family Reviewer would plausibly miss the same mistake). Fix: re-invoke the fetcher via `src.override` with version-substituted `tag`/`rev` and `hash = fakeHash`. `FetchzipRequest` gains a `current_version` field for the substitution.

**`review-cross-family-attestation` scorer widened.** The earlier shape only verified `patcher_family_observed`, blindly trusting `reviewer_family` and `rule_honored`. wget2 reruns surfaced both under-verified fields being fabricated (Reviewer claimed `anthropic-claude` for itself and `rule_honored=false` despite the routing config genuinely pairing different Anthropic families). Widened scorer now verifies all three claims against deterministic ground truth from `replay.json` + the reviewer's invocation `model_id`. Score 0.0 on any single fabrication, with `details.fabricated_fields[]` enumerating which specific claims diverged. Five new tests for the previously-silent fabrication modes.

**Reproducer prompt v2.** New `prompts/reproducer.v2.md` (runner default updated). Targets the v1 failure modes surfaced by wget2: (1) new "Sandbox model" preamble explaining that a CVE described as network-shaped doesn't automatically need network in the test, (2) refusal rule 3 reworded with a mandatory pre-refusal check ("verify the trigger truly needs network, not merely that the canonical exploit path is network-shaped"), (3) worked example showing the inline-fixture pattern (`pkgs.writeText` malicious metadata + `${unpatched}/bin/foo --metadata=${evil-metadata}` + specific SIGNAL substrings), (4) forbidden-fetcher rule strengthened to enumerate all fetcher classes and state "without exception" with rationale (v1's list-shaped enumeration left `fetchFromGitLab` ambiguous).

**Corpus grows to 9 real-CVE + 19 synthetic.** New bundles since v0.2.0: `CVE-2025-69194--wget2` (model-attested chain run; preserved as evidence of the cohort split — Reviewer accepted the patch end-to-end, Reproducer hit the contract limit). traefik reclassified from auto-merge to `human-review-required` (`ineligible-cherry-pick-required`) after `bundle-linux-cert.yml` surfaced the Go 1.24→1.25 toolchain dependency the Patcher contract refuses. New synthetic fixtures: `CVE-0000-0012`..`CVE-0000-0018` (one per Steward rule 6-12 deny path), `CVE-0000-0019`/`CVE-0000-0020` (reviewer-attested allow + rule-13 deny).

**Cost reporting + throughput rollup (`trace report`).** Per-role invocation sidecars (`<role>-invocation.json`) capture token usage and provider-side pricing inputs at the moment of the run, surviving replay archives. `agents/cost.py` prices Anthropic input/output/cache_creation/cache_read tokens. `trace report throughput` rollups across on-disk artifacts produce both JSON and human readouts. First honest cost snapshot landed 12 May 2026: ~$0.22 mean cost-per-merge-ready (N=3, model-attested bundles only).

**Documentation.** `docs/CORPUS.md` gains the v0 cohort-split section with curation filters. `eval/HARVESTING.md` documents the new `patch_shape` axis with explicit "filter on overlay for sandbox-positive" guidance. `docs/REPRODUCER_V1.md` §4.1 (Linux build host requirement) and §4.2 (Builder-knob escape hatches). `docs/DECISIONS.md` accumulates the slice arcs: Builder ASAN contract (3a), libtiff Linux cert close + 2 corpus-expansion findings, traefik reclassification, reviewer-attested formalisation (slice C), wget2 model-attested run (fetchzip bug caught by Reviewer), prompt v2, patch_shape axis, cohort-split decision.

### Test suite

**1030 passing, 30 skipped** (network-gated). Up from 972 / 30 at v0.2.0. New coverage:
* Builder dispatch_outcome enum + per-outcome path (refused-no-patch, refused-no-reproducer, patch-apply-failed, infra-failure, instrumentation-malformed).
* ASAN instrumentation contract (sibling schema, runner threading, linker verification).
* Steward rules 6-13 (one positive + one deny fixture each).
* SPEC §5 reviewer-attested auto-merge path (synthetic allow + deny anchors).
* `auto_merge_evidence_path` schema enforcement (auto-merge file requirements split by evidence path).
* `patch_shape` axis on candidate + corpus schemas (enum validation + presence in every row).
* Widened cross-family scorer (5 new tests for previously-silent fabrication modes).
* Reproducer prompt v2 (parser rejects fetchFromGitLab + the wider fetcher enumeration).
* `fetchzip_prefetch._build_expression` post-fix shape (`src.override (orig: ...)` with version-substring substitution).

### Boundaries (updated for v0.3.0)

The v0.2.0 boundaries hold. Two are sharpened by the cohort-split work:

* **Auto-merge real-CVE-signed bundle.** Still gated. v0.3.0's reviewer-attested path is the implemented model-attested route to auto-merge, but the corpus has no real-CVE bundle that clears every gate in production: wget2 cleared Patcher + Reviewer but hit the Reproducer contract limit; traefik cleared Patcher + Reviewer but hit a Go-toolchain dependency outside the Patcher contract; bind + mbedtls have no Reviewer evidence at all in the current corpus state. A clean reviewer-attested allow anchor needs a candidate with all three signals coherent at the pinned rev.
* **Sandbox-positive model-attested Reproducer.** Documented as deferred to v0.1. The two real-CVE sandbox-positive bundles (libtiff, mruby) remain deterministic-no-model evidence of the deterministic path. The model-attested sandbox-positive path needs either resolver relaxation or parser relaxation; both are v0.1 design branches.

Full v0 non-goal list: [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## v0.2.0 — 7 May 2026

### Scout autonomously feeds the bundle pipeline

v0.1.0 demonstrated the inner chain (Patcher → Reviewer → Builder →
Reproducer → Steward) producing verified bundles from hand-staged
inputs. v0.2.0 brings Scout online: hourly cron discovery from real CVE
feeds, scoping against a pinned nixpkgs graph snapshot, and
construction of a `scout-input.json` rich enough that
UpstreamRefResolver can decide eligibility without further input.
First non-curated `eligible` verdicts produced (4 kernel CVEs in cron
run 25466617594).

**Scout discovery + polling.** New modules under `agents/scout/`:
`feed_client.py` (HTTP transport for Vulnpatch dossier + NVD direct,
exponential-backoff retry), `discovery.py` (windowed CVE-id discovery
from NVD with cursor + retry queue persisted under `state/`),
`poll_one.py` (per-CVE poll orchestrator), `processor.py` (graph-scan
+ candidate-ref extraction + auto-resolve), `batch_cli.py`
(single-Python-invocation batch driver), `auto_prefetch.py`
(orchestrator for FOD-hash extraction). Hourly schedule via
`.github/workflows/scout-cron.yml`; longitudinal run records committed
to `data/scout-runs.jsonl` with `[skip ci]` to keep the workflow
budget bounded.

**Vulnpatch dossier normalizer.** `agents/feed_normalizers/dossier.py`
lifts the aggregator response into `scout-input` while preserving the
trust boundary: `feed` reflects the underlying authoritative source
(NVD > GHSA > OSV); aggregator metadata lands in the optional
`aggregator` block which Steward explicitly ignores. CPE matches +
pname hints + references + version bounds extracted; references
classified by host + NVD tag. New `version_bounds[].provenance` enum
distinguishes `fixed-version-from-status-list` and
`pre-release-from-status-list` (slice 5h status-list fallback) from
the structured / free-text affected-list paths.

**UpstreamRefResolver tightening.** New review triggers and
ineligibility paths, every one fixture-pinned in
`tests/resolver/fixtures/`:
* `ambiguous-fixed-version` (lessThanOrEqual / versionEndIncluding
  bounds where next-semver math is undefined for v0)
* `pre-release-target` (rc/alpha/beta target versions blocked from
  auto-merge)
* `placeholder-target-version` (no version bound derivable, target
  fell back to current_version, made explicit in scout-input rather
  than detected downstream by equality)
* `no-target-version-derived` (legacy backstop)
* downgrade refusal (`current >= target` filtered before verdict)
* identity refusal (`target == current` routes to ineligible)

**Steward patcher-readiness gate (slice 5c.1).** Three new Rego rules
in `policy/steward_route.rego`: auto-merge-eligible now requires
`prefetch_hashes` populated AND no `prefetch_skips` with
`required_for_patch == true`. Reaches Steward as
`patcher-not-ready:missing-prefetch-hashes` and
`patcher-not-ready:prefetch-skipped:<slot>` reason codes. Gates
correctly even when the resolver returns `eligible` but no FOD hash is
derivable (the kernel-CVE shape).

**Auto-prefetch chain.** Three layered env gates (TRACE_REAL_PREFETCH,
TRACE_REAL_FETCHZIP) for plain `fetchurl` and `fetchFromGitHub`
sources. fetchurl path uses `auto_prefetch_high_confidence`
filtered to `package-url-template` rule; fetchFromGitHub path uses
`prefetch_fetchzip` (fetchzip-aware FOD extraction via `nix-build`
with `lib.fakeHash`). Per-class metrics:
`plain-fetchurl-{attempted,succeeded,failed}`,
`fetchFromGitHub-{attempted,succeeded,failed,present-but-skipped}`,
`fetchzip-present-but-skipped`, `go-mod-vendor-present-but-skipped`.

**Path resolver fixes (slice 5j).** Cron run instrumentation revealed
nix-eval returns `meta.position` paths in alt store-source entries
that don't exist on the runner (Determinate Nix's flake registry
resolves internal `<nixpkgs/...>` imports lazily; the resulting store
entry is never archived). Two-stage fix: accept paths under any
`/nix/store/<32hex>-source/` tree (the `nix-eval-alt-source`
strategy); when the alt-source path doesn't exist on disk, re-root the
relative path under the trace flake's archived `nixpkgs_root` (the
`nix-eval-rerooted` strategy). `path_resolver_diag` aggregates per-
bucket; `path_resolver_message` carries a truncated raw message
per-entry. Defense-in-depth `relative_to` check after reroot guards
against symlink escapes.

**git.kernel.org commit-URL recognition (slice 5i).** Linux kernel
CVEs publish patches as kernel.org cgit links rather than github
mirrors. Four shapes recognized: `/stable/c/<sha>`,
`/torvalds/c/<sha>`, `/linus/<sha>`, full cgit
`/pub/scm/.../<tree>.git/commit/?id=<sha>`. Anything outside these
four stays unmatched (a fabricated `repo_url` would silently break the
patcher; ineligible-no-fix-available is recoverable). Dossier
classifier extended in lockstep so kernel URLs land at
`kind=upstream-commit` rather than `kind=other`.

**Status-list version_bounds fallback (slice 5h).** When no
`status: "affected"` entry produces a structured or free-text bound,
infer one from `status: "unaffected"` entries with provenance
preserved. Recovered 92/100 placeholder-target-version cases on day-1
measurement (2 confirmed-recovered with real fix versions, 83
correctly identified as already-fixed in nixpkgs via downgrade
filter).

**CPE matching upgrade.** `agents/scout/cpe_matcher.py` now does
real wildcard-aware CPE matching with version-range gating against
the NVD `/cpes/2.0` dictionary. Per-page retry on 5xx; retries absorb
transients but don't mask sustained outages.

**Backfill CLI.** `python -m agents.scout.backfill` for windowed
catch-up runs over a closed CVE-id range. Used to seed cron state for
the first hourly run.

**Patcher CLI.** New `agents/patcher/cli.py` for inbox-driven model
invocation: default model `claude-opus-4-7`, $1.00 soft / $3.00 hard
budget, exit codes 0/10/11/12/13/14/64. Adapter injection for tests.

**`trace bundle pr-snippet`.** New CLI rendering the upstream PR
evidence block from a finalized bundle (citations, signing identity,
verifier command). TDD-first; eight tests covering the rendering
contract.

**Where kernel CVEs land in v0.** Eligible verdict, real fix commits,
honest `human-review-required` with structured
`patcher-not-ready:prefetch-skipped:src.hash` reason. The kernel
`mainline.nix` constructs src inside `buildLinux`, not via a flat
`src = fetchurl`, so there is no single FOD hash to bump. A
kernel-aware patcher is a separate research arc; for v0 the bundles
are honestly bucketed and reviewable.

### CI infrastructure

**Cron hardening.** Hourly `.github/workflows/scout-cron.yml` pinned
to `:17` with longitudinal record append. Two opa-install fixes:
SIGPIPE under `set -o pipefail` (`opa version | head -1` exited 141
when head closed the pipe early); curl retry on transient 5xxs from
the OPA download CDN. Cron also resolves nixpkgs root via
`nix flake archive --json | jq` and passes `--use-nix-eval` for the
long-tail attr layout. Discovery cursor cached via
`actions/cache@v4`; retry queue carries failed CVEs across runs.

**Snapshot builder.** `.github/workflows/scout-snapshot.yml` builds
the nixpkgs graph snapshot via `--no-drv-paths` to avoid OOM. Drift
detection workflow alerts when the snapshot ages beyond threshold.

**FlakeHub OIDC.** Cron runs gracefully skip auto-prefetch when the
snapshot is missing (transient FlakeHub login failures observed; cron
continues without enrichment rather than failing the run).

### Documentation

**DECISIONS.md.** Substantial accumulation: full-chain integration
test landed; signing identity locked; signed real-CVE bundle (uriparser
run 25075869027); fork-build cohort (bind green, traefik + mbedtls
honest v0 limits); no qualified anthropic-side Reproducer model on v0
(later amended); libtiff CVE-2024-13978 dispatch (Builder saturates
GitHub Actions; v1 Hydra-graduation criterion landed concretely);
mruby CVE-2025-7207 deterministic-no-model corpus seed; Scout funnel
investigation closure (slices 5h, 5i, 5j) on 7 May 2026.

### Test suite

**972 passing, 30 skipped** (network-gated). Up from 651 / 24 at
v0.1.0. New coverage:
* Scout HTTP feed client (canned-fixture + retry semantics).
* Vulnpatch dossier normalizer (33 tests including version_bounds
  status-list provenance).
* CVE discovery + windowed cursor.
* Inbox writer atomicity.
* Inbox processor scan + auto-resolve.
* Resolver fixtures for every new verdict + trigger.
* Steward Rego rules for patcher-readiness gates.
* Auto-prefetch orchestrator (env-gating, plain-fetchurl, FOD
  extraction, aggregate metrics, path-resolver diagnostic bucketing).
* Path resolver alt-source + reroot.
* git.kernel.org commit-URL regex + malformed-rejection.

### Boundaries (no change from v0.1.0)

The deliberate non-goals from v0.1.0 still hold: no auto-merge for
real-CVE-signed bundles (gated on sandbox-positive Reproducer corpus +
Builder saturation graduation), no live-API CI on every push (gated on
per-workspace budget caps), no Hydra integration, no novel-vuln
discovery, no UI, no direct upstreaming. Kernel CVEs route to
human-review-required by design as documented above. Full list:
[`docs/DECISIONS.md`](docs/DECISIONS.md) section
*Deliberate non-goals for v0*.

---

## v0.1.0 — 28 April 2026

### Public-readiness milestone

The first milestone where an external reviewer can audit a trace bundle end-to-end without reading the CI workflow source. Repository graduates from research scaffolding to public-auditable artifact flow.

**Corpus.** Five real-CVE bundles + three synthetic shapes under `traces/example/`. The seed map is a single-page index at [`docs/SEED_INDEX.md`](docs/SEED_INDEX.md). Three distinct `human-review-required` sub-shapes are exercised (major-version-jump, blast-radius-exceeds-threshold, cross-family-pair-unavailable) and two distinct auto-merge deny shapes (rule-7 no-reproducer-feasible, rule-8 Builder-saturation). Two bundles are deterministic-no-model corpus seeds (libtiff, mruby); the rest are model-attested (`claude-opus-4-7` Patcher).

**Signed bundle production.** v0 ledger has four CI dispatches across `hello`, `bind`, `uriparser`, `libtiff`, with one signed real-CVE bundle (uriparser, run 25075869027, Rekor log_index 1397922891). Honest deny-on-deny demonstrated: bind on rule-7 (no reproducer in corpus), libtiff on rule-8 (Builder timed out on the patched build, the v1 Hydra-graduation criterion landing concretely). No false-positive signatures.

**Signed bundle verification.** New CLI:

```sh
gh run download <run-id> --name steward-smoke-<bundle> --dir ./artifact
trace bundle verify ./artifact
```

Reads `subject_regex` and `oidc_issuer` from `policy/signing-identity.json`; verifies against `bundle.canonical.json` (the frozen pre-sign snapshot, not the post-mutation `bundle.json`). cosign must be on PATH. Fails sensibly on missing artifact, missing canonical, missing cosign, cosign-verify-failure. Source: `tools/trace_cli/verify.py`. Seven-test coverage of input-validation paths and cosign invocation shape.

**Drift guards.**
* `tests/docs/test_seed_index.py`: five-test guard binding SEED_INDEX to `bundle.json` + `replay.json`. Catches new-bundle-not-indexed, deleted-bundle-still-cited, kind-cell drift, family-cell drift.
* `tests/cli/test_signing_identity.py::test_subject_regex_resolves_to_an_actual_workflow_on_disk`: catches workflow rename without policy update. The locked regex now binds to a file that must exist on disk.

**Public-readiness paperwork.** Apache-2.0 license; `SECURITY.md` with coordinated-disclosure policy + locked signing identity for verifiers; `CONTRIBUTING.md` with DCO + Apache-2.0 inbound + commit-message conventions; em-dash sweep across user-facing prose.

**Orientation docs.** [`docs/CONCEPTS.md`](docs/CONCEPTS.md) (the *what*), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (directory + control flow), [`docs/SEED_INDEX.md`](docs/SEED_INDEX.md) (per-bundle map). README cross-links them and provides a verify quickstart.

**Test suite.** 651 passing, 24 skipped (network-gated). CI green across `rego fmt + check`, `schema + steward`, and `graph (rust)` jobs.

**Honest CI coverage boundary.** Re-examined after a "did we test the agents in CI?" challenge:

* `tests/integration/test_full_chain.py` runs every push. It scaffolds a fresh bundle, executes Patcher → Reviewer → Reproducer → Builder → Steward end-to-end, and asserts Steward allows. Each role's runner, parser, replay writer, provenance writer, and scorer code paths execute for real; cross-family rule enforcement is verified; the bundle output validates against schemas + Rego policy.
* What's mocked at that test boundary: the model API transport (`FakeAdapter` returns pre-canned response strings instead of hitting Anthropic) and the nix-build transport (`FakeBuildRunner` returns canned exit codes). Everything *between* "response text arrives" and "Steward verdict" is the real production code.
* What's NOT in CI on every push: live Anthropic API calls; live `nix-build`; bundle signing (Steward's signing-and-Rekor path is exercised by manual `workflow_dispatch` on `.github/workflows/steward.yml`, not by `ci.yml`; four such dispatches across `hello`, `bind`, `uriparser`, `libtiff` form the v0 signing ledger).
* The model-attested bundles under `traces/example/` (uriparser, mbedtls, openssl_3, systemd, traefik, bind) were produced by local dev runs against the real Anthropic API; CI replays them through the integration tests' static-fixture validators. The agent *runner* code path that produces those bundles is exercised end-to-end on every CI push via `test_full_chain` with FakeAdapter substituting only the API transport.

The remaining genuine CI gap is **live API + live nix-build** on every push. Both are non-trivial: live API requires budgeted secrets and rate-limit handling; live nix-build requires a Linux runner with sufficient disk + 30-min+ time budget (the libtiff Builder-saturation deny on run 25077946199 is the concrete proof).

### Current v0 boundaries

What this milestone deliberately does **not** ship:

* Auto-merge real-CVE-signed bundle. Gated on (a) sandbox-positive Reproducer corpus extension AND (b) v1 Hydra / large-runner / pre-warmed-cache infrastructure clearing Builder's 30-min saturation point.
* ~~Live-model CI integration.~~ **Closed 28 April 2026** at the transport layer: `.github/workflows/live-anthropic-smoke.yml` + `tests/integration/test_live_anthropic_smoke.py` pair runs one round-trip against `claude-haiku-4-5-20251001` on manual dispatch. First green run: [25086008154](https://github.com/Ad-Astra-Computing/trace/actions/runs/25086008154), 1.24s test exec, <\$0.001 cost. Live-model CI on **every push** remains gated on Anthropic adding per-workspace budget caps (account-wide today; uncapped CI churn would accrue real cost).
* Live-build CI integration. `FakeBuildRunner` substitutes `nix-build`. A live variant needs a Linux runner with sufficient disk and a >30-min time budget, which is the same constraint as the v1 Hydra graduation criterion.
* Bundle signing on every push. Today's `ci.yml` does not sign; signing lives behind `workflow_dispatch` on `.github/workflows/steward.yml`. Auto-signing on every push would mint hundreds of Rekor entries for development churn; the manual-dispatch boundary is deliberate.
* Direct upstreaming to nixpkgs. Bundles are evidence; humans pick what to upstream and when.
* Hydra integration. Deferred to v1 when Builder saturates Actions (libtiff already saturates; the criterion landed concretely on 28 April 2026).
* Novel-vulnerability discovery. Separate lane, separate guardrails, deferred.
* UI. Bundles live as files; review happens in GitHub PRs against the fork.
* ASAN-aware Builder profile. Required to reproduce mruby-class CVEs sandbox-positively. Out of v0; mruby ships as a deterministic-no-model `human-review-required` seed in the meantime.

Full v0 non-goal list: [`docs/DECISIONS.md`](docs/DECISIONS.md) section *Deliberate non-goals for v0*.
