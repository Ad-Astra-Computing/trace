# Security policy

## Reporting a vulnerability

If you find a security issue in trace itself (the tooling, the bundle pipeline, the signing path, the policy gates), please report it privately. Do not open a public GitHub issue.

* **Email**: security@adastracomputing.com
* **GitHub Security Advisory**: <https://github.com/Ad-Astra-Computing/trace/security/advisories/new>

We aim to acknowledge reports within 3 business days and to publish a fix or mitigation within 30 days for high-severity issues. Coordinated disclosure timelines are negotiable; we'll work with you on a window that lets you publish your finding when it's ready.

## What's in scope

* The trace tooling under `agents/`, `tools/`, `policy/`, `prompts/`, `.github/workflows/`.
* The bundle schema (`policy/bundle-schema.json` and the per-role schemas).
* The Steward gate (`policy/steward.rego`) and the signing identity (`policy/signing-identity.json`).
* The CI workflows that produce signed bundles, particularly `.github/workflows/steward.yml`.

Specifically in scope:

* **Steward bypass**: any input that produces `allow=true` despite violating one of the documented merge-gate invariants in `docs/STEWARD_V1.md`.
* **Signing identity drift**: any path that produces a Rekor entry whose `subject` does not match `policy/signing-identity.json:paths.sigstore-keyless-oidc-github-actions.subject_regex`.
* **Replay/provenance disagreement that escapes rule-5**: any bundle where `provenance.jsonl` and `replay.json` disagree on a model_invocation but the bundle still signs.
* **Schema escape**: any bundle that signs with a `signed_manifest` that doesn't faithfully reflect the replay-critical files on disk.
* **Prompt injection that exfiltrates or causes off-path actions**: see [`docs/SECURITY_PROMPT_INJECTION.md`](docs/SECURITY_PROMPT_INJECTION.md) for the threat model. Reports of injected content that escapes the strict-output contract are welcome.
* **Supply-chain risks**: see [`docs/SECURITY_CI_SUPPLY_CHAIN.md`](docs/SECURITY_CI_SUPPLY_CHAIN.md). Any path that lets a third party influence what gets signed under the locked workflow identity.

## What's out of scope

* CVEs in the *underlying nixpkgs derivations* that trace produces patches for. Those are upstream issues. trace's job is to produce evidence; report the CVE upstream or via your usual disclosure channel.
* Issues in dependent projects (Sigstore, cosign, Rekor, OPA, nixpkgs, the Anthropic / OpenAI SDKs). Report those upstream.
* Findings in pre-baked deterministic-no-model corpus seeds (e.g. `traces/example/CVE-2024-13978--libtiff/`) where the seed's `README.md` explicitly marks the artifact as not-yet-model-attested. Those are explicit interim documents; their content is checked against public sources, not produced by trace.

## What to include in a report

* The trace commit SHA you observed the issue against (see `git rev-parse HEAD`).
* A minimal reproducer: a bundle directory, a workflow dispatch input, a CLI invocation. Whatever it takes to walk us through the issue.
* The expected vs observed behaviour, in terms of the specific Steward rule, schema property, or workflow step.
* Your preferred disclosure timeline.

## Coordinated disclosure

We follow coordinated disclosure. We will:

1. Acknowledge your report within 3 business days.
2. Assign a primary contact and CVE id (if appropriate).
3. Work with you on a fix and a publication window.
4. Credit you in the resulting advisory unless you ask us not to.

If you discover that a *signed bundle* itself misattests something (e.g. a bundle's `signed_manifest` claims a file is signed but the file's content has changed, or a verifier accepts a bundle whose signature should have failed), that's a particularly load-bearing finding, please flag it as such in your report.

## Scope of the locked signing identity

The signing identity in `policy/signing-identity.json` is pinned to:

* **subject_regex**: `^https://github\.com/Ad-Astra-Computing/trace/\.github/workflows/steward\.yml@refs/(heads/main|tags/v[0-9][^/]*)$`
* **oidc_issuer**: `https://token.actions.githubusercontent.com`

A signature claiming this identity is trace's. A signature claiming any other identity is not, even if the certificate is otherwise valid. Verifiers should pin against both fields with `cosign verify-blob --certificate-identity-regexp ... --certificate-oidc-issuer ...`.

If you observe a Rekor entry signed under the locked identity that you cannot reconcile with a public commit on `main` or a published tag, that's a high-severity finding and should be reported immediately.

## PGP

Reporters who prefer PGP can request the current public key by email. We don't publish a long-lived key here so the rotation cadence stays under our control.
