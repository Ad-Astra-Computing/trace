# trace

Agent-owned nixpkgs fork for merge-ready CVE evidence bundles.

> **v0 thesis.** trace tests whether agent systems can turn known upstream
> security fixes into maintainer-trustworthy nixpkgs evidence bundles
> faster than current human workflows.

trace is a research artifact, not a product. v0 is an upstream-fix
integrator for nixpkgs (not a generic auto-patcher, not a
vulnerability-discovery system). The boundaries are deliberate and
documented; see [Boundaries](#boundaries) below.

## Status

* **Latest tag**: [v0.4.0](CHANGELOG.md) (F1–F7 contract slice on
  wget2: drop-only patches, per-side `passthru.test`, gated SIGNAL
  emission, Builder pins `pkgs` to bundle nixpkgs, unpatched.test
  runs against pre-patch tree; wget2 retired as v0.1 anchor with new
  sandbox-PoC suitability filter codified in the corpus).
* **Phase**: research artifact. Bundles live in `traces/example/` as
  files; review happens in PRs against the fork. No UI.
* **Frozen scope**: nixpkgs `nixos-unstable`, derivations with
  `passthru.tests`, upstream fixes with a release or tag, rebuild
  closure under 500. Everything else is out of scope; see SPEC §6.

## What trace does

A CVE flows through six roles, each with an explicit contract
(`agents/<role>/`, schema in `policy/`, deny-able by Steward):

1. **Scout** discovers CVEs from NVD + Vulnpatch, scopes them against
   a frozen nixpkgs graph snapshot, lifts version bounds and commit
   refs into a `scout-input.json`. Runs hourly under
   `.github/workflows/scout-cron.yml`.
2. **UpstreamRefResolver** decides eligibility (eligible /
   eligible-requires-human-review / ineligible-no-fix-available)
   based on whether a derivable target version and a recognized
   fix-commit URL exist. Deterministic, no model.
3. **Patcher** produces the diff plus a `patch-rationale.md`.
   Model-attested or deterministic-no-model. Cannot decide its own
   eligibility.
4. **Reviewer** adversarially reviews the patch. Different model
   family from Patcher (cross-family rule).
5. **Builder** runs the patched derivation and the affected
   `passthru.tests` under `nix-build`. Saturating Actions on a real
   CVE is the v1 Hydra-graduation criterion.
6. **Reproducer** demonstrates the vulnerability or refuses with a
   principled reason (sandbox-incompatible, no PoC public, etc.).

**Steward** then evaluates the assembled bundle against
`policy/steward_route.rego` and routes to one of four states:
auto-merge, human-review-required, advisory-only, or
ineligible-rejected. Auto-merge bundles are signed via Sigstore
keyless OIDC against a locked workflow identity; the signature anchors
to a Rekor transparency-log entry verifiable with `cosign verify-blob`.

The seed corpus is [nine real-CVE bundles](docs/SEED_INDEX.md)
exercising distinct shapes (auto-merge, both honest deny paths,
three human-review sub-shapes, model-attested vs
deterministic-no-model).

## What v0 can and cannot do today

v0.3.0 ships two paths to auto-merge, and they don't currently overlap.
The split is structural, not incidental, and it's worth seeing up
front.

* **Model-attested reviewer-attested auto-merge** (SPEC §5; Steward
  rule 13). For bundles whose CVE class doesn't admit a sandbox
  Reproducer, the cross-family witness is the Reviewer. Patcher emits
  the diff, Reviewer (different model family) accepts, the bundle
  ships `reproducer-refusal.json` documenting why no Reproducer is
  feasible. Patch shapes that flow here: `version-bump`, `mixed`
  (~39/51 corpus candidates).
* **Deterministic sandbox-positive Reproducer** (the libtiff and
  mruby template). Hand-authored `resolver-input.json` + hand-written
  `reproducer.nix` that filters the CVE patch out of `old.patches` to
  reconstruct the unpatched derivation. Patch shapes that flow here:
  `overlay` (11/51 corpus candidates). Not model-attested at the
  Reproducer stage.

**No corpus candidate today hits both paths.** The overlay-shaped
candidates that would support sandbox-positive Reproducers all lack a
release tag containing the fix, so UpstreamRefResolver routes them to
`ineligible-cherry-pick-required` before the chain runs. The
version-bump candidates that pass the resolver can't ship a
sandbox-positive Reproducer because reconstructing unpatched src needs
a network fetcher (which the Reproducer parser forbids). This is
recorded as the v0 design state in [`docs/CORPUS.md`](docs/CORPUS.md)
§ "v0 cohort split", along with curation filters for harvesting
deliberately for each path. Two unification paths are tracked as v0.1
design branches; neither shipped in v0.3.0.

## Walk one bundle

[`traces/example/CVE-2025-67899--uriparser/`](traces/example/CVE-2025-67899--uriparser/)
is the first signed real-CVE bundle in the v0 ledger.

**The CVE.** uriparser 0.9.9 → 1.0.0 (the project's first stable major
release). Unbounded recursion in `ParseMustBeSegmentNzNc` with
comma-heavy input (CWE-674).

**The bundle artifacts.** Every file is part of the contract:

* `finding.json`, `resolver-input.json`, `upstream-ref.json`. Scout +
  UpstreamRefResolver outputs. Pin the CVE to a specific nixpkgs
  attribute and a target version.
* `patch.diff`. Byte-identical to the historical nixpkgs fix at
  `e9da914af2cd`. Produced by Patcher (`claude-opus-4-7`).
* `patch-rationale.md`. Patcher's narrated reasoning, citing the
  upstream commit and the `versionEndExcluding` constraint.
* `package.nix`, `maintainers.json`, `impact.json`. The downstream
  packaging context.
* `reproducer-refusal.json`. A principled refusal under rule 3:
  triggering unbounded recursion in the build sandbox would exhaust
  the sandbox's stack limit and crash the build process itself.
  Steward accepts the refusal because the refusal is itself evidence.
* `bundle.json`. The frozen pre-sign snapshot. `kind =
  human-review-required`, `kind_reason =
  major-version-jump-requires-review`.
* `replay.json`. Full provenance: nixpkgs rev, prompt hash, model and
  provider metadata, tool versions, policy version. Anyone can replay
  the run.
* `scoring-report.json`. Per-rule scorer output.

**Verifying the signature.**

```sh
gh run download 25075869027 --name steward-smoke-uriparser --dir ./uriparser-artifact
trace bundle verify ./uriparser-artifact
```

Anchored at `rekor_log_index = 1397922891`, signed against the locked
workflow identity in
[`policy/signing-identity.json`](policy/signing-identity.json). cosign
must be on PATH. The signed bytes are `bundle.canonical.json` (the
frozen pre-sign snapshot, not the post-mutation `bundle.json`).

**Pipeline-bug provenance.** The first run for this bundle is preserved
under
[`_first-run-archive/`](traces/example/CVE-2025-67899--uriparser/_first-run-archive),
intentionally. It surfaced a real Patcher contract bug
(`github-release-archive` confidence + `nix-prefetch-url` against
`fetchFromGitHub` produces a divergent hash). Deleting the archive
would erase the evidence that the pipeline was wrong before it was
right.

## Boundaries

What v0 deliberately does not ship:

* **Auto-merge for kernel CVEs.** The kernel's `mainline.nix` builds
  src inside `buildLinux`, not via a flat `src = fetchurl`. There is
  no single FOD hash to bump. Kernel CVEs reach Steward as `eligible`
  with a structured `patcher-not-ready:prefetch-skipped:src.hash`
  reason and route to human-review-required. A kernel-aware patcher
  is a separate research arc.
* **Auto-merge real-CVE-signed bundle.** v0.3.0 ships the
  reviewer-attested path (Steward rule 13) as the implemented
  model-attested route, but the corpus has no real-CVE bundle that
  clears every gate in production today: wget2 cleared Patcher +
  Reviewer cleanly but hit the Reproducer contract limit; traefik
  cleared Patcher + Reviewer but its 3.6.8 needs a Go-toolchain bump
  the Patcher contract refuses; bind + mbedtls have no Reviewer
  evidence at all in the current corpus state. A clean
  reviewer-attested allow anchor needs a candidate with all three
  signals coherent at the pinned rev. See [v0 cohort
  split](#what-v0-can-and-cannot-do-today) above.
* **Live-API CI on every push.** Live-Anthropic transport is wired and
  proven (run 25086008154 on a haiku round-trip), but
  every-push-live-API is gated on per-workspace budget caps.
* **Direct upstreaming.** Bundles are evidence; humans pick what to
  upstream and when.
* **Hydra integration.** Deferred to v1.
* **Novel-vulnerability discovery.** Separate lane, separate
  guardrails, deferred.
* **UI.** Bundles are files; review is PRs.

Full v0 non-goal list: [`docs/DECISIONS.md`](docs/DECISIONS.md) section
*Deliberate non-goals for v0*.

## Reading order

* [docs/CONCEPTS.md](docs/CONCEPTS.md). What trace is, the key
  concepts (bundles, roles, kinds, cross-family rule, signing).
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Directory layout,
  control flow, what pins what.
* [docs/SEED_INDEX.md](docs/SEED_INDEX.md). One-page map of the eight
  real-CVE bundles in `traces/example/`.
* [SPEC.md](SPEC.md). v0 design, rev 3 (22 April 2026).
* Per-role contracts under [docs/](docs/) (`BUILDER_V1.md`,
  `REPRODUCER_V1.md`, `STEWARD_V1.md`, `SIGNING_V1.md`).
* [docs/MODEL_EVAL_PLAN.md](docs/MODEL_EVAL_PLAN.md). Model
  qualification methodology.
* [docs/DECISIONS.md](docs/DECISIONS.md). Append-only log of why the
  project looks the way it does.
* [CHANGELOG.md](CHANGELOG.md). Tagged release notes.

## Development

The default dev shell lives in `flake.nix`:

```sh
nix develop
```

Tests:

```sh
pytest
```

The Rust graph crate has its own shell, opt-in via `nix develop .#graph`.

## Pre-commit hooks

Local hooks run a secret scanner (gitleaks) plus light hygiene checks.
While the repo is private, GitHub's free secret scanning is not
available, so the local hook is the safety net before anything reaches
origin. To enable, install [pre-commit](https://pre-commit.com) (it is
on PATH inside `nix develop`, or `pipx install pre-commit` works too),
then run `pre-commit install` once in the repo root to wire up the git
hook. Run `pre-commit run --all-files` to scan the whole tree on
demand. Path allow-lists for public CVE/GHSA fixtures live in
`.gitleaks.toml`.

## License + signing identity

Apache-2.0 (see [LICENSE](LICENSE) and
[CONTRIBUTING.md](CONTRIBUTING.md) for inbound terms).

Every bundle Steward signs anchors a Rekor transparency-log entry to a
locked workflow identity. The verifier-side identity (issuer,
subject regex, expected workflow ref) lives in
[`policy/signing-identity.json`](policy/signing-identity.json) and is
the authoritative pin: rotate this file (with a SECURITY.md notice) if
the workflow ever moves. See [docs/SIGNING_V1.md](docs/SIGNING_V1.md)
§5 for the full rationale and the verifier protocol.

For coordinated disclosure: [SECURITY.md](SECURITY.md).
