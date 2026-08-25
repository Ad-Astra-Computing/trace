# trace

An agent-owned nixpkgs fork that turns known upstream security fixes into
signed, merge-ready CVE evidence bundles.

trace is a research artifact, not a product. It tests one question: can an agent
system take a disclosed CVE and a known upstream fix and produce a maintainer
trustworthy nixpkgs evidence bundle, signed against a locked workflow identity. It
is an upstream-fix integrator, not a generic auto-patcher and not a
vulnerability-discovery system. The scope boundaries are deliberate; see
[Boundaries](#boundaries).

## Quick start

```sh
# Flakes and nix-command must be enabled (nix.conf: experimental-features =
# nix-command flakes), or prefix with --extra-experimental-features.
nix develop          # dev shell from flake.nix
pytest                # full suite, offline, no API spend
```

A bundle is a directory of files under `traces/example/CVE-XXXX-XXXXX--<attr>/`.
A complete bundle records a CVE, the affected derivation, the proposed patch, the
proof the patch fixes the vulnerability, and the routing verdict; some in-repo
directories are staged or single-role fixtures rather than complete signed
bundles. To read one:

```sh
ls traces/example/CVE-2025-26625--git-lfs/
cat traces/example/CVE-2025-26625--git-lfs/finding.json
```

Signature verification runs against the signed artifact a Steward run produces,
not the in-repo copy. The run emits a `bundle.canonical.json` frozen snapshot,
and `trace bundle verify <downloaded-dir>` verifies the cosign signature over that
snapshot, including the embedded Rekor transparency-log proof and the locked
workflow identity. (Steward checks the per-file replay hashes at signing time.)
See [`docs/SIGNING_V1.md`](docs/SIGNING_V1.md) for the download-and-verify
protocol.

## What trace does

A CVE flows through a chain of roles, each with an explicit contract under
`agents/<role>/`, a schema in `policy/`, and a final Steward that can deny the
result:

1. **Scout** discovers CVEs from NVD and Vulnpatch, scopes them against a frozen
   nixpkgs graph snapshot, and records version bounds and fix-commit refs. Runs
   hourly under `.github/workflows/scout-cron.yml`.
2. **UpstreamRefResolver** decides eligibility from whether a derivable target
   version and a recognized fix-commit URL exist. Deterministic, no model.
3. **Cartographer** records the downstream packaging context: the affected
   derivation's `impact.json` (rebuild closure) and `maintainers.json`.
4. **Patcher** produces the diff and a `patch-rationale.md`. Model-authored or
   deterministic. It cannot decide its own eligibility.
5. **Reviewer** adversarially reviews the patch against the upstream ground
   truth. It must be a different model family from the Patcher (the cross-family
   rule), so the reviewer and the author never share context.
6. **Reproducer** demonstrates the vulnerability with a sandbox test that fails
   on the unpatched build and passes on the patched one, or refuses with a
   principled reason (the CVE class needs a network socket, no public PoC, and
   so on).
7. **Builder** runs the patched derivation and the affected `passthru.tests`
   under `nix-build`, and runs the Reproducer's two test arms.

**Steward** then evaluates the assembled bundle against `policy/steward.rego` and
routes it to one of four states: auto-merge, human-review-required,
advisory-only, or ineligible-rejected. Auto-merge bundles are signed with Sigstore
keyless OIDC against a locked workflow identity; the signature anchors to a Rekor
entry that anyone can check with `trace bundle verify` or `cosign verify-blob`.

## Status

Latest tag: [v0.7.0](CHANGELOG.md) (21 July 2026). The corpus in
`traces/example/` holds 169 real-CVE directories (August 2026, excluding the
`CVE-0000-*` synthetic fixtures), of which 103 carry a `bundle.json` evidence
bundle and the rest are staged or single-role fixtures. The Reviewer runs a LoRA
adapter on `Qwen2.5-Coder-14B-Instruct`; its pilot corpus is 84 cert-green
positives and 55 negatives (27 July 2026 snapshot), and the adapter passes its
gate. This is not a benchmark result and makes no frontier-parity claim.

Where the pipeline stands on running without a human:

- **Patcher and Reviewer run without a human.** The Patcher authors the fix, the
  Reviewer verifies it cross-family against the upstream fix, and dozens of
  bundles have passed a full Linux cert (`bundle-linux-cert.yml`) with a signed
  manifest.
- **The Reproducer authors its behavioral test without a human** with Sonnet or
  Haiku as of August 2026. Earlier this stage needed a human because the model
  output failed to parse; that was a format-handling limit, now fixed. See
  `docs/DECISIONS.md`.
- **Corpus-wide auto-merge is ongoing, not finished.** A bundle reaches
  auto-merge on one of two paths: a cert-green sandbox Reproducer, or a
  reviewer-attested route where the CVE class admits no sandbox reproducer and
  the bundle ships a principled `reproducer-refusal.json`. Either way the fix
  must be cert-green and the signature must verify. Many bundles route instead to
  human-review-required for documented policy reasons: major version jumps, large
  rebuild closures, or a CVE class with no sandbox reproducer. That routing is
  the policy working as designed.

Bundles live as files; review happens in pull requests against the fork. There is
no UI. Frozen scope: nixpkgs `nixos-unstable`, derivations with `passthru.tests`,
upstream fixes that ship in a release or tag, and a rebuild closure under 500.

## Fork PRs are accuracy artifacts

trace opens pull requests against its own `Ad-Astra-Computing/nixpkgs` fork from
cert-green bundles. These measure how close the pipeline's output lands to the
human upstream fix. They are not merge candidates and are never submitted to
nixpkgs. The fork is the staging ground; the signed bundles are the artifact.

## Boundaries

What trace deliberately does not do:

- **Auto-merge for kernel CVEs.** The kernel builds its source inside
  `buildLinux`, not from a flat `src = fetchurl`, so there is no single
  fixed-output hash to bump. Kernel CVEs route to human-review-required. A
  kernel-aware patcher is a separate arc.
- **Direct upstreaming.** Bundles are evidence. Humans pick what to upstream and
  when.
- **Novel-vulnerability discovery.** A separate lane with separate guardrails,
  out of scope here.
- **Live-API CI on every push.** The live-Anthropic path is wired and proven, but
  running it on every push is gated on per-workspace budget caps. Live model
  calls are research spend.
- **Hydra integration and a UI.** Both deferred.

The full non-goal list is in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Reading order

- [`docs/CONCEPTS.md`](docs/CONCEPTS.md): what trace is, and the core ideas
  (bundles, roles, kinds, the cross-family rule, signing).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): directory layout, control flow,
  and what pins what.
- [`docs/SEED_INDEX.md`](docs/SEED_INDEX.md): a per-bundle map of the corpus.
- [`SPEC.md`](SPEC.md): the v0 design.
- Per-role contracts under [`docs/`](docs/): `BUILDER_V1.md`, `REPRODUCER_V1.md`,
  `STEWARD_V1.md`, `SIGNING_V1.md`.
- [`docs/DECISIONS.md`](docs/DECISIONS.md): an append-only log of why the project
  looks the way it does.
- [`CHANGELOG.md`](CHANGELOG.md): tagged release notes.

## Development

```sh
nix develop          # default dev shell
pytest               # full suite
```

The Rust graph crate has its own shell: `nix develop .#graph`.

Local git hooks run a secret scan plus house-style and invisible-character
checks before a commit reaches origin. See `CONTRIBUTING.md` for how contributions
are signed and reviewed.

## License and signing identity

Apache-2.0. See [`LICENSE`](LICENSE) and [`CONTRIBUTING.md`](CONTRIBUTING.md) for
inbound terms.

Every signed bundle anchors a Rekor transparency-log entry to a locked workflow
identity. The verifier-side identity (issuer, subject regex, expected workflow
ref) lives in [`policy/signing-identity.json`](policy/signing-identity.json) and
is the authoritative pin. See [`docs/SIGNING_V1.md`](docs/SIGNING_V1.md) for the
verifier protocol.

For coordinated disclosure, see [`SECURITY.md`](SECURITY.md).
