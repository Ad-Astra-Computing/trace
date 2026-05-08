# Changelog

Append-only release notes. Tagged releases land at the top; unreleased work accumulates under a `Unreleased` heading until a tag cuts.

The decision log at [`docs/DECISIONS.md`](docs/DECISIONS.md) is the *why* and the running story; this file is the *what shipped*. They reference each other where useful but do not duplicate.

---

## Unreleased

(none)

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
