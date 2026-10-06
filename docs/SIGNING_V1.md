# Bundle signing v1 — contract specification

**Status:** locked. v0 bundles ship signed via **Sigstore keyless OIDC through GitHub Actions**, with the trace Steward CI workflow as the bound identity. (B) Ad Astra-held key signing is deferred to a future hardening path; this document records the conditions under which the project would graduate from (A) to (B).

**Supersedes:** SPEC.md §7 open question 2 (sigstore OIDC vs Ad Astra-held key) — choice locked here as Sigstore keyless OIDC.

**Related artifacts:**
- `policy/bundle-schema.json:signed_manifest` — the schema the signature covers.
- `policy/signing-identity.json` — the locked identity policy verifiers pin against.
- `policy/steward.rego:rule-4` — already enforces "every replay-critical file listed in `signed_manifest.signed_files` with matching sha256."

---

## 0. Purpose

Every trace bundle that leaves the Steward CI workflow carries a `bundle.sig` produced by `cosign sign-blob` against the bundle's canonical-shape hash. The signature has two consumers:

1. **Maintainers reviewing a trace PR** — they verify the bundle came from the trace project's CI before trusting any embedded patch / hash / claim.
2. **Auditors replaying a bundle weeks or months later** — they verify the signature still anchors to a Rekor transparency log entry.

Both consumers verify against the **identity policy** (repo + workflow path + ref constraints), not just signature validity. A signature from a different workflow at the same repo, or from a fork, fails the identity check even if the cryptographic signature is well-formed.

---

## 1. Why Sigstore keyless OIDC

Locked decision per the 2026-04-28 hand-off:

- **Operationally cheap.** No private-key custody during pipeline stabilisation. No Yubikey rotation, no HSM provisioning, no escrow ceremony.
- **Auditable via Rekor.** Every signature is recorded in the public sigstore transparency log. Verifiers can independently confirm the bundle was signed at a specific timestamp without trusting any centralised identity provider beyond GitHub.
- **Matches project shape.** trace is a research artifact with CI-driven bundle production and a public audit trail as a feature. Sigstore's "publish everything" stance aligns with that.

The (B) Ad Astra-held key path stays open for the conditions in §6.

---

## 2. Identity policy (the trust statement)

A trace `bundle.sig` is **trustworthy** when ALL of the following identity-policy fields match:

| field | required value (v0) |
|---|---|
| `signer.identity_issuer` | `https://token.actions.githubusercontent.com` (GitHub Actions OIDC issuer) |
| `signer.identity_subject` | matches the regex `^https://github\.com/Ad-Astra-Computing/trace/\.github/workflows/steward\.yml@refs/(heads/main\|tags/v[0-9].*)$` |

Plain words: signed by the **Ad Astra Computing trace project's Steward workflow**, running on the `main` branch or a release tag, **not** by an arbitrary GitHub Actions workflow anywhere.

This is the meaning of `signed_manifest.signer` per `policy/signing-identity.json`:

- ✓ "signed by the trace Steward CI workflow on main"
- ✓ "signed by the trace Steward CI workflow on a release tag"
- ✗ "signed by any GitHub workflow anywhere" (fork or random repo passes pure cosign-verify but fails identity policy)
- ✗ "signed by the Ad Astra Computing legal entity with offline custody" (not what v0 provides; reserved for §6 graduation)

`policy/signing-identity.json` carries this constraint as a structured document so the verifier (a CLI invocation of `cosign verify-blob` or a downstream tool) reads identity policy from one canonical place rather than every consumer hard-coding it.

---

## 3. Schema interaction

`policy/bundle-schema.json` already supports the v0 contract — `signed_manifest.algorithm` accepts `sigstore-cosign-v1`. v1 of this contract additionally permits these optional fields on `signed_manifest`, so a bundle's manifest can carry the Rekor pointers when present:

```json
"signed_manifest": {
  "algorithm": "sigstore-cosign-v1",
  "signer": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
  "identity_subject":   "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
  "identity_issuer":    "https://token.actions.githubusercontent.com",
  "rekor_log_index":    142_857_309,
  "rekor_uuid":         "24296fb24b8ad77a...",
  "signed_files": [
    { "path": "bundle.json",        "sha256": "..." },
    { "path": "finding.json",       "sha256": "..." },
    ...
  ]
}
```

`identity_subject` and `identity_issuer` carry forward the OIDC claim the workflow presented at signing time so verifiers can cross-check against `policy/signing-identity.json`. `rekor_log_index` and `rekor_uuid` are the Rekor transparency-log coordinates; both are optional in v0 because not every signing path produces them at write time (cosign returns them; minisign would not), and the `signer` field still carries the canonical identity string regardless.

---

## 4. Signing workflow

The Steward GitHub Actions workflow (forthcoming, separate landing) will:

1. Receive the finalised bundle directory.
2. Compute the canonical-shape hash of every file listed in `signed_manifest.signed_files`. This is the same hash the bundle's `files[<path>].sha256` already records, just re-collected at sign time as a tamper guard.
3. Invoke `cosign sign-blob --bundle bundle.sig <canonical-input>` using the workflow's GitHub-issued OIDC token. cosign records the signature into the Rekor public log automatically; the response carries the log index + uuid.
4. Populate `signed_manifest.identity_subject`, `signed_manifest.identity_issuer`, `signed_manifest.rekor_log_index`, `signed_manifest.rekor_uuid` in the bundle's `bundle.json`.
5. Commit the now-signed bundle (or post it to the merge PR).

The Rekor log entry is the durable proof. `bundle.sig` is the local artifact; Rekor is the timeline.

---

## 5. Verification (downstream)

A maintainer or auditor verifies a trace bundle with:

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/Ad-Astra-Computing/trace/\.github/workflows/steward\.yml@refs/(heads/main|tags/v[0-9].*)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle bundle.sig \
  <canonical-input>
```

The locked identity-policy fields in `policy/signing-identity.json` are exactly the values to pass to `--certificate-identity-regexp` / `--certificate-oidc-issuer`. The downstream verifier never hard-codes them; they're read from the policy document so updates to the workflow path (a project rename, a renamed branch policy) propagate cleanly.

The CLI wrapper `trace bundle verify <artifact-dir>` does this automatically:

```bash
gh run download <run-id> --name steward-smoke-<bundle> --dir ./artifact
trace bundle verify ./artifact
```

The `<artifact-dir>` must contain `bundle.canonical.json` (the frozen pre-sign snapshot, the actual signed bytes) and `bundle.sig`. `bundle.json` itself is the post-sign-mutation copy carrying populated `signed_manifest.identity_subject` + Rekor coordinates, and is **not** what verification runs against; the canonical snapshot is. cosign must be on PATH; trace's dev shell does not bundle it because verifiers are typically external. Source code: `tools/trace_cli/verify.py`. Failure modes: `EXIT_NOT_FOUND` (artifact / canonical / sig / cosign / policy missing), `EXIT_VERIFY_FAILED` (cosign returned non-zero on identity mismatch, bad signature, Rekor inclusion-proof failure, etc.).

---

## 6. Graduation path to (B) — Ad Astra-held key

This v1 contract stays in (A) until ANY of the following becomes true:

1. **Offline / non-GitHub signing requirement.** A consumer specifically requires a signature not contingent on GitHub's OIDC infrastructure (e.g., air-gapped audit, regulator request).
2. **Maintainer requests an organisation-held key identity.** A nixpkgs maintainer or a downstream consumer asks for "signed by Ad Astra Computing Inc." rather than "signed by a CI workflow." This is a real operational difference.
3. **CI platform continuity.** trace migrates off GitHub Actions and the workflow-bound identity becomes invalid; an Ad Astra-held key gives continuity across platform moves.
4. **Project graduation.** trace transitions from research artifact to operational service with a long-term support commitment; an organisation-held key signals that maturity step.

Until any of those hold, (A) is the v0 default. The graduation work, when triggered, would:

- Add `minisign-ed25519` (already in the schema enum) or extend with `cosign-key-v1` as a new algorithm.
- Add a public-key-fetch endpoint or an embedded public key in the verification policy.
- Update `policy/signing-identity.json` to record the key identity / fingerprint.
- Keep (A) Sigstore as a fallback verification path so existing signed bundles remain verifiable.

---

## 7. What this contract does NOT cover

- **provenance.jsonl signing.** SPEC reserves this as separately signed by Scout-issued action records; not part of `bundle.sig`. Out of scope here.
- **The `cosign` invocation specifics inside the GH Actions workflow YAML.** That lives in the Steward workflow definition (forthcoming separate commit). This document is the contract; the workflow is its implementation.
- **Key-rotation policy for (B).** Reserved for the graduation cycle.

---

## 8. Open questions parked

1. **`bundle.sig` location.** v0 places it inside the bundle directory (alongside `bundle.json`). Some sigstore patterns put the signature in a sidecar repository instead. Either is valid; v0 keeps it local for replay determinism.
2. **Rekor entry retention.** Sigstore's public Rekor log is intended to be permanent, but downstream consumers may want a redundancy. v1 does NOT mirror Rekor entries to a separate location. v2 may add an Ad Astra-controlled mirror as a hedge.
3. **Workflow path stability.** The locked identity regex includes the literal workflow path `.github/workflows/steward.yml`. If that file is ever renamed, EVERY consumer's verification breaks. The `policy/signing-identity.json` document is the single update point — but downstream verifiers using cached copies of the regex would also need to refresh.

---

## 9. Payload reconciliation incident, 2026-10-06

`cosign verify-blob` proves `bundle.canonical.json` was signed. It says nothing about whether the payload files beside it (`patch.diff`, `reproducer.nix`, the rest of `signed_manifest.signed_files`) are the bytes that were actually signed, and nothing in `trace pr` or `trace bundle verify` checked that reconciliation before this date. An audit run against every bundle under `traces/example/` found none that reconciled without qualification. Three distinct causes, not one:

**Finalize signed claims about files that did not exist.** `signed_manifest.signed_files` carried a placeholder hash (`"d" * 64`) for every replay-critical file absent at finalize time (`sbom-delta.json` in all bundles with a signature, `reproducer-refusal.json` / `review-refusal.json` / `passthru-tests.json` in most), plus a self-referential `bundle.json` entry that can never match once Steward writes `signer` / `rekor_log_index` back into that file post-sign. This is noise, not drift, and is fixed going forward: `finalize_bundle` no longer puts a placeholder-hashed or self-referential entry into `signed_files` (`tools/trace_cli/bundle.py`). `trace bundle verify --payload-dir` and `trace pr`'s reconciliation grandfather both patterns on already-signed bundles rather than failing on them.

**Thirty bundles had no committed `bundle.canonical.json`.** For twenty-seven of those, the Rekor digest embedded in `bundle.sig` was checked against `bundle.json` at each commit in the bundle's history and matched byte-for-byte at the commit the Steward run actually signed (three of the thirty are `CVE-0000-*` / `CVE-2024-13978--libtiff` fixtures carrying a placeholder, not a real signature). The canonical was never lost; it was never committed as a separate file. All twenty-seven were restored from that commit (not re-signed: the original Rekor entry is the attestation).

**A real reconciliation sweep against every signed bundle's current payload bytes (`cosign` + `trace bundle verify --payload-dir`, run against all 66 signed bundles after the restoration above) found the problem is broader than the initial sample suggested.** Of the 63 real (non-fixture) signed bundles: 27 reconcile cleanly end to end (signature valid, every payload byte matches what was signed). 36 carry drift. Of those 36, five have the security-relevant files themselves replaced after signing, with no new signature: `CVE-2021-41581--libressl-x509-mailbox-backport` (`patch.diff` + `patch-rationale.md`, overwritten 2026-09-05 by a live Patcher run during a Tier-B-to-Tier-A promotion the day's `DECISIONS.md` entry already records as not promotable), and `CVE-2026-40198--netcidrlite-uncompressed-ipv6-backport`, `CVE-2026-40199--netcidrlite-ipv4mapped-backport`, `CVE-2026-45190--netcidrlite-unicode-newline-backport`, `CVE-2026-45191--netcidrlite-cidrmask-backport` (`reproducer.nix`, two of which also carry a drifted `patch.diff`). Two of the netcidrlite five (`40198`, `40199`) already have fork review PRs open (`#41`, `#40`) citing a cert run against the now-drifted reproducer. The remaining 31 of the 36 drift only in bookkeeping files the signature also covers but `trace pr` never ships (`replay.json`, `review.md`, and occasionally `upstream-ref.json` / `finding.json` / `impact.json` / `maintainers.json`), not in the patch or the fixture itself.

**What changed as a result:**

- `trace bundle verify --payload-dir` (now the only payload-reconciliation path; see §5) grandfathers the sentinel-hash and `bundle.json`-self-entry cases on old signatures, and fails closed on everything else (`tools/trace_cli/verify.py:_check_payload`).
- `trace pr` no longer trusts `bundle.json`'s own hash fields. It verifies `bundle.canonical.json`'s signature, reconciles the trust-critical top-level fields (`bundle_id`, `cve_id`, `nixpkgs_rev`, `kind`, `kind_reason`) against the canonical, and reconciles every signed payload file's bytes, before anything is staged for a PR (`tools/trace_cli/pr.py:_verify_against_canonical`). `build.json` is excluded from that reconciliation by design: on a Tier-B→Tier-A promotion it is installed after signing, per the bootstrap recipe's own "install build.json, then finalize again" step, so it is legitimately absent from the originally signed manifest.
- `bundle finalize` refuses to rewrite the manifest of an already-signed bundle (`bundle.sig` present) unless called with `--supersede-signature`, which archives the current signature's Rekor coordinates to `superseded-signatures.json` first. The old signature and canonical remain recoverable from git history either way; nothing is deleted or overwritten in place.
- None of the 36 drifted bundles are re-signed as part of closing this finding; `docs/SEED_INDEX.md` names all 36 and `trace pr` now refuses every one of them until a Steward run covers the current bytes. Re-signing the 31 bookkeeping-only bundles and re-certifying the 5 payload-drift bundles are tracked as separate corpus-maintenance work.
