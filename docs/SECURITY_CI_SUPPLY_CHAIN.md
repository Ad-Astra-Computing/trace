# CI supply chain — locked v1 contract

**Status:** locked. v1 installs OPA in every workflow via the official `open-policy-agent/setup-opa` action, pinned by full commit SHA. The previous direct-curl path with an embedded sha256 checksum was structurally weak against compromise of the OPA project's release infrastructure (a single attacker push that updates the binary AND the published `.sha256` would defeat the in-line checksum). The action layer adds a verifiable git history and a SHA-pinned install logic that an attacker would need to subvert separately.

**Supersedes:** the prior `OPA_VERSION` + `OPA_LINUX_AMD64_SHA256` + `curl | sha256sum -c` block that lived in `.github/workflows/ci.yml`, `.github/workflows/real-prefetch-smoke.yml`, and `.github/workflows/steward.yml`.

**Related artifacts:**
- `.github/workflows/ci.yml` — three install sites (test, lint-rego, graph jobs).
- `.github/workflows/real-prefetch-smoke.yml` — one install site.
- `.github/workflows/steward.yml` — one install site (the signing workflow).
- `docs/SIGNING_V1.md` — the bundle-signing contract this CI supports.

---

## 0. Purpose

trace's CI installs three external toolchains: Nix, Rust, OPA. Each one has a distinct trust model and a distinct install path. This document is the locked contract for the OPA install path. Nix is installed via `DeterminateSystems/nix-installer-action` pinned by full commit SHA. Rust is installed via `actions-rust-lang/setup-rust-toolchain` (graduation candidate; see §6). cosign for the signing workflow is installed via `sigstore/cosign-installer@v3` tag-pinned (see §3).

OPA is the entry point for every Steward gate run, including the signing workflow that produces `bundle.sig`. A compromised OPA binary in any CI job could silently rewrite gate decisions and emit valid signatures over poisoned bundles. Hardening this install path is therefore a precondition for trusting any signed bundle the Steward workflow produces.

---

## 1. What we trust (v1)

Listed in order from highest to lowest assumed integrity, with what each grants:

| trust anchor | what it grants |
|---|---|
| **GitHub.com platform** | repository contents, action SHAs, release artifact hosting, OIDC token issuer for sigstore. Compromise here breaks the entire model. |
| **`open-policy-agent/setup-opa` repository at commit `b2b258e089860efaadaaf71bf6e3aecb4a3eeff1`** | the install logic that resolves a pinned `OPA_VERSION` to a release asset URL, downloads it, and verifies it against the GitHub-published `.sha256`. Pinned by full commit SHA: an attacker pushing a new commit to `setup-opa@main` does NOT affect trace's CI. |
| **`open-policy-agent/opa` GitHub release `v1.0.1`** | the `opa_linux_amd64_static` binary and the matching `.sha256` sidecar. `setup-opa` fetches both via the GitHub releases API authenticated with `${{ github.token }}`. |
| **Sigstore (Fulcio + Rekor)** | the keyless signing identity infrastructure for `bundle.sig`. Used by the Steward workflow only; not part of the OPA install path. |

Plain words: we trust the GitHub platform AND a specific frozen commit of the OPA install action AND the GitHub-served release manifest. Compromise of any single one of those, in isolation, breaks the chain. Compromise of TWO or more in coordination is the structural threat the future graduation step in §6 hedges against.

---

## 2. What we verify (v1)

| layer | mechanism | failure mode caught |
|---|---|---|
| action SHA pin | `open-policy-agent/setup-opa@b2b258e08…` | rogue push to `setup-opa@main` after we last reviewed it. |
| OPA version pin | `with: { version: v1.0.1, static: true }` | `setup-opa` silently resolves to a newer or compromised release. The action validates the requested semver against the GitHub release list. |
| binary checksum | `setup-opa` internally compares the downloaded asset against the `.sha256` sidecar published in the same GitHub release | bit-flip or transport-layer corruption between GitHub and the runner. |
| version preflight | `opa version | grep -F "Version: 1.0.1"` in `ci.yml`'s test + lint-rego jobs | install logic regression that yields a usable but wrong-version binary. |

We do **NOT** verify a sigstore signature on the OPA release because `open-policy-agent/opa` v1.0.1 ships only an unsigned `.sha256` sidecar. No `.sig`/`.pem`/`.bundle` assets are present (verified against the v1.0.1 release on 2026-04-27). When OPA upstream begins publishing sigstore signatures, §6 graduates to add `cosign verify-blob` against the OPA-team OIDC identity.

---

## 3. Action pinning convention

Every third-party action used in trace CI is pinned by full commit SHA, with a trailing `# vN.N.N` tag comment so Dependabot has a target to update against:

```yaml
uses: open-policy-agent/setup-opa@b2b258e089860efaadaaf71bf6e3aecb4a3eeff1 # v2.4.0
uses: DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25 # v22
uses: DeterminateSystems/magic-nix-cache-action@565684385bcd71bad329742eefe8d12f2e765b39 # v13
```

Two exceptions are tolerated in v1:

- `actions/*` (first-party GitHub) — `actions/checkout@v6`, `actions/cache@v5`, `actions/upload-artifact@v5`. These tags are owned by GitHub itself; pinning them to a SHA hardens against a hypothetical first-party compromise but offers little net trust gain over the platform we already trust as the topmost anchor in §1.
- `sigstore/cosign-installer@v3` — the official sigstore install action, tag-pinned. Listed for graduation in §6.

Resolve a new SHA when bumping the tag with:

```bash
git ls-remote https://github.com/open-policy-agent/setup-opa.git refs/tags/vN.N.N
```

Update the tag comment in the same edit so the trail stays scrutable.

---

## 4. Why this beats the prior curl-with-checksum path

The previous block embedded `OPA_LINUX_AMD64_SHA256` literally in workflow YAML and downloaded `opa_linux_amd64_static` from `openpolicyagent.org/downloads/...`. Two structural weaknesses:

1. **Single-point compromise of the OPA release infrastructure.** If an attacker who controls `openpolicyagent.org` updates the binary, they can update the published `.sha256` sidecar in the same push. A trace contributor bumping `OPA_VERSION` would copy the new (poisoned) sha256 verbatim into the env block. The check passes; the binary is hostile.
2. **No git-history evidence trail.** The download URL has no commit history. A maintainer reviewing a PR that bumps `OPA_VERSION` cannot diff "what changed in the install logic between v1.0.0 and v1.0.1."

The action-based path closes both gaps:

- `setup-opa@<sha>` is itself a frozen commit. An attacker who compromises OPA's release infrastructure but NOT the action repository at the pinned SHA still has to bypass the action's verification logic.
- The action's source is reviewable on GitHub at the exact commit. Any future bump produces a Dependabot PR that lists the upstream changes between SHAs, surfacing them for review.

The two structural compromise scenarios have not gone away; they have moved one trust hop further out and require two distinct pieces of attacker capability rather than one.

---

## 5. Threat model — what's still in scope

This contract reduces but does not eliminate supply-chain risk. Explicitly still in scope:

- **GitHub platform compromise.** A compromised GitHub.com can serve a different binary at the same release URL or a different action SHA at the same ref. We accept this as the topmost trust anchor.
- **Coordinated compromise of OPA upstream + setup-opa action repo.** An attacker who controls both can push a new `setup-opa` release that intentionally fetches a poisoned OPA binary and skips checksum verification. SHA-pinning means we'd only be exposed on the next manual bump cycle, but the bump itself is the risk window.
- **Runner host compromise.** The `ubuntu-latest` runner image, the network path between the runner and GitHub, the `nix develop` shell. None of this changes under v1.

The future hardening directions in §6 hedge against subsets of these.

---

## 6. Graduation path

This v1 contract stays locked until ANY of the following becomes true:

1. **OPA upstream publishes sigstore signatures on releases.** When `open-policy-agent/opa` adds `.sig` / `.bundle` / `.cert` assets to a release, replace the action's internal `.sha256` check with `cosign verify-blob --certificate-identity-regexp <opa-team-oidc-identity>`. Either keep `setup-opa` and configure it to verify, or fall back to a curl + cosign block depending on the action's surface at that time. Tracked: <https://github.com/open-policy-agent/opa/issues> for any "release signing" issue.
2. **Self-hosted artifact mirror.** trace stands up an Ad Astra-controlled artifact store (e.g. an S3 bucket or an OCI registry) that mirrors verified OPA release artifacts after a maintainer-signed verification ceremony. Workflows download from the mirror instead. Removes GitHub.com as the runtime trust anchor for the OPA binary. Cost: storage + maintenance + the sign-off ritual on each upgrade.
3. **`actions/*` SHA pinning.** Move `actions/checkout`, `actions/cache`, `actions/upload-artifact` from major-tag pins to full-SHA pins. Likely follows a Dependabot config update that targets these alongside third-party actions.
4. **`sigstore/cosign-installer` SHA pinning.** Same shape as item 3. Currently tag-pinned at `v3`; bump to a full-SHA pin in the same Dependabot pass.
5. **Reproducible build of OPA from source.** Build OPA inside the `nix develop` shell from a pinned upstream commit and a hash-locked Go module set. Removes the binary download path entirely. High effort, high reward; reserved for a future hardening cycle.

Until any of those graduate, v1 is the v0 default.

---

## 7. What this contract does NOT cover

- **The cosign install path for the Steward signing workflow.** Lives in `docs/SIGNING_V1.md` as part of the bundle-signing contract. Tag-pinned `sigstore/cosign-installer@v3` is the v0 default there; SHA-pinning is graduation item §6.4.
- **The Rust install path for the graph job.** `actions-rust-lang/setup-rust-toolchain@v1` is currently tag-pinned. Acceptable for v1 because the graph job does not touch signing material; will move to SHA-pin alongside the §6.3 sweep.
- **Runner image trust.** `ubuntu-latest` resolves to whatever GitHub publishes; we do not pin runner image digests.
- **Network-layer integrity.** TLS + GitHub.com is the layer. Trace does not run an mTLS-pinned proxy.

---

## 8. Operational runbook

**Bumping OPA:**

1. Pick the new `OPA_VERSION` (e.g. `v1.0.2`).
2. Confirm `open-policy-agent/setup-opa` knows about it: the action queries the GitHub release list, so any tagged release from `open-policy-agent/opa` works once the tag is published.
3. Update `OPA_VERSION` in all three workflows in the same commit. Grep for stragglers:

   ```bash
   grep -rn "OPA_VERSION" .github/workflows/
   ```

4. Run `gh workflow run ci.yml --ref <branch>` and watch.
5. If a new major of `setup-opa` ships, bump the SHA + tag-comment in the same commit. Resolve the SHA per §3.

**Suspecting a compromise:**

1. Roll back `OPA_VERSION` to the last known-good value.
2. If the suspicion is on the action itself, roll the SHA back to the previous pinned commit (`b2b258e089860efaadaaf71bf6e3aecb4a3eeff1` is v1's choice).
3. File an issue against `open-policy-agent/opa` AND `open-policy-agent/setup-opa` describing the symptom.
4. Pause the Steward signing workflow (`workflow_dispatch` only, so no scheduled runs need disabling) until upstream confirms.

---

## 9. Open questions parked

1. **Should v1 keep the in-line sha256 as a belt-and-braces check on top of the action?** No; doing so silently relies on the action exposing a way to skip its own verification while we re-do it, which the action does not. Keeping a duplicate check would require a second curl block running in parallel, which adds attack surface (a second download path) without adding trust (the action already does the check). Drop sha256 from the env block; rely on the action.
2. **Self-hosted runners.** trace v1 uses `ubuntu-latest` only. A move to self-hosted runners would change the threat model materially and would warrant a v2 of this contract.
3. **OPA build provenance.** OPA does not publish SLSA provenance for v1.0.1. When upstream begins publishing it, the §6.1 graduation can fold provenance verification in alongside the cosign step.
