# Changelog

Append-only release notes. Tagged releases land at the top; unreleased work accumulates under a `Unreleased` heading until a tag cuts.

The decision log at [`docs/DECISIONS.md`](docs/DECISIONS.md) is the *why* and the running story; this file is the *what shipped*. They reference each other where useful but do not duplicate.

---

## Unreleased

### Public-readiness milestone (28 April 2026)

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
* Live-model CI integration. `test_full_chain` runs the entire role chain end-to-end with FakeAdapter substituting the API transport; every other code path is real. A live-model variant on every push needs budgeted Anthropic secrets + rate-limit handling.
* Live-build CI integration. `FakeBuildRunner` substitutes `nix-build`. A live variant needs a Linux runner with sufficient disk and a >30-min time budget, which is the same constraint as the v1 Hydra graduation criterion.
* Bundle signing on every push. Today's `ci.yml` does not sign; signing lives behind `workflow_dispatch` on `.github/workflows/steward.yml`. Auto-signing on every push would mint hundreds of Rekor entries for development churn; the manual-dispatch boundary is deliberate.
* Direct upstreaming to nixpkgs. Bundles are evidence; humans pick what to upstream and when.
* Hydra integration. Deferred to v1 when Builder saturates Actions (libtiff already saturates; the criterion landed concretely on 28 April 2026).
* Novel-vulnerability discovery. Separate lane, separate guardrails, deferred.
* UI. Bundles live as files; review happens in GitHub PRs against the fork.
* ASAN-aware Builder profile. Required to reproduce mruby-class CVEs sandbox-positively. Out of v0; mruby ships as a deterministic-no-model `human-review-required` seed in the meantime.

Full v0 non-goal list: [`docs/DECISIONS.md`](docs/DECISIONS.md) section *Deliberate non-goals for v0*.
