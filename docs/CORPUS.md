# trace v0 corpus

The set of CVE bundles under `traces/example/` is the corpus trace ships as evidence that the role chain produces what it claims to produce. This document classifies every bundle in the corpus, names which dimension of the v0 contract each bundle exercises, and explains why each non-auto-merge bundle is non-auto-merge.

**Status (2026-05-13):** 9 real-CVE bundles + 19 synthetic / deny-path fixtures. The synthetic set is the test infrastructure (one fixture per Steward rule's deny path, plus structural fixtures for schema validation); the real-CVE set is the evidence layer.

The corpus is intentionally small. trace's claim isn't "we automate CVE remediation across nixpkgs" — it's "we produce merge-ready evidence bundles a human can accept or reject in minutes." A small, well-classified corpus serves that claim better than a large, hand-wavy one.

---

## Real-CVE bundles (8)

### Auto-merge candidates

| bundle | reason it's auto-merge | Reproducer state |
|---|---|---|
| `CVE-2024-13978--libtiff` | full chain succeeded on darwin-aarch64; auto-merge gated on Linux-cert workflow per Steward rule 12 | reproducer.nix present, SIGNAL substrings verified on Darwin; Linux portability is a known open question (DECISIONS 2026-05-12) |
| `CVE-2024-49195--mbedtls` | minimal-change single-hash bump; Patcher emitted a clean fetchpatch + Steward rule 6-11 satisfied via fixture build.json | no reproducer; the patch story (single fetchpatch on a wrapper package) is self-evident |
| `CVE-2025-13878--bind` | similar to mbedtls but on a 178-line `package.nix`; Patcher's refusal precision proven (the bundle has `reproducer-refusal.json` rule 3, no live reproducer) | Reproducer refused under rule 3 — the crash class is "denial-of-service via malformed BRID/HHIT records (CWE-617 reachable assertion)" with no public PoC and uncertain sandbox reachability |

(traefik was previously listed here; reclassified to human-review-required on 2026-05-13 after the Linux cert run surfaced a Go-toolchain dependency the Patcher contract cannot cleanly cherry-pick. See its row in the human-review table.)

### Human-review-required

| bundle | kind_reason | why human-review |
|---|---|---|
| `CVE-2025-4598--systemd` | `blast-radius-exceeds-threshold` | reverse-closure 50000 entries (bucket `>5000`); v0 threshold = 500. Steward rule 4. See bundle README. |
| `CVE-2025-9230--openssl_3` | `blast-radius-exceeds-threshold` | reverse-closure `>5000`; same shape as systemd. The two paired bundles form the rule-4 cohort. |
| `CVE-2025-67899--uriparser` | `major-version-jump-requires-review` | upstream fix only in 1.0.0 (major jump from 0.9.9); Patcher refused under rule 8 (no minor-version backport available). Reproducer also refused (rule 3, stack-consumption recursion class). |
| `CVE-2025-7207--mruby` | `cross-family-pair-unavailable` | only one Anthropic Sonnet model qualified for Reproducer under the v0 cross-family rule; pair with Patcher (Opus) leaves no Sonnet variant for cross-family. Reproducer authored hand-on with ASAN-instrumented mruby (slice 3a, 12 May 2026). |
| `CVE-2026-25949--traefik` | `ineligible-cherry-pick-required` | minimal CVE-driven diff is contract-correct but doesn't build at the pinned nixpkgs rev: traefik 3.6.8 needs Go ≥ 1.25, which would require the maintainer-driven `buildGo124Module → buildGo125Module` toolchain bump the Patcher contract forbids. Surfaced by cert run 25777382142, slice C 2026-05-13. |
| `CVE-2025-69194--wget2` | `sandbox-poc-requires-network` | (CVSS 9.8 Metalink path-traversal.) Drove the F1–F7 contract slice across six cert dispatches (DECISIONS 2026-05-13 → 2026-05-17). Contract layer functioned end-to-end on cert 6: `patched_build` succeeded, both reproducer-side derivations built clean, both binaries ran against the metalink fixture, both honestly exited `PREDICATE FAILED` (no SIGNAL minted). Retired as v0.1 anchor because wget2's metalink PoC requires a fetchable URL (wget2 rejects `file://` / `data:` schemes), and the Nix build sandbox is network-isolated. Preserved in the corpus as evidence the framework refused to fake a green result; the bundle ships F1's `patch-drop-rationale.md` and the F7-correct reproducer.nix shape as reference. |

Six of eight real-CVE bundles are non-Reproducer-shaped (mbedtls / bind / systemd / openssl_3 / uriparser / traefik). The Reproducer dimension is load-bearing only where the CVE-class signal is producible deterministically in a sandbox without instrumentation that trace's v0 Builder doesn't yet ship. That's a deliberate cohort split, not a gap.

---

## Synthetic / deny-path fixtures (17)

Synthetic bundles exist to test the Steward decision surface and the schema layer. Each fixture's `expect.json` records `steward_expected` + (for invalid bundles) the `steward_rule_id` that must fire.

### Steward rule-by-rule deny fixtures

One fixture per non-trivial Steward rule, in `CVE-0000-001N--<descriptive-name>` form:

| fixture | rule | what it asserts |
|---|---|---|
| `CVE-0000-0010--patcher-fixture-dispatchable` | (none) | structural Patcher-input fixture; pre-Builder cohort-1 |
| `CVE-0000-0011--full-chain-auto-merge` | (allow) | the v1 Steward 'allow' anchor — every rule satisfied |
| `CVE-0000-0012--auto-merge-missing-builder` | rule-6 | `build.json` absent → deny |
| `CVE-0000-0013--auto-merge-builder-dispatch-failed` | rule-7 | `build.dispatch_outcome != ok` → deny |
| `CVE-0000-0014--auto-merge-patched-build-failed` | rule-8 | `patched_build.outcome != succeeded` → deny |
| `CVE-0000-0015--auto-merge-proxy-reproducer` | rule-9 | reproducer `is_proxy=true` → deny |
| `CVE-0000-0016--auto-merge-repro-signal-failed` | rule-10 | `repro-patched-passes` scored `0.0` → deny |
| `CVE-0000-0017--auto-merge-reviewer-rejected` | rule-11 | Reviewer verdict `reject` → deny |
| `CVE-0000-0018--auto-merge-non-linux-build` | rule-12 | `build.host.system != x86_64-linux` → deny |
| `CVE-0000-0019--reviewer-attested-allow` | (allow) | reviewer-attested cross-family witness path; rule-7 escape + rule-13 supporting artifacts satisfied |
| `CVE-0000-0020--reviewer-attested-missing-refusal` | rule-13 | reviewer-attested without `reproducer-refusal.json` → deny |

### Schema / replay deny fixtures (9000-series)

| fixture | concern |
|---|---|
| `CVE-0000-9001--advisory-has-patch` | advisory-only bundles must not carry `patch.diff` (schema-invalid; Steward never reached) |
| `CVE-0000-9002--auto-merge-missing-reproducer` | auto-merge requires Reproducer artifacts (schema-invalid for bundle without `reproducer.nix`) |
| `CVE-0000-9003--replay-provenance-mismatch` | replay.json + provenance.jsonl must agree on role invocations |
| `CVE-0000-9004--low-confidence-auto-merge` | Patcher confidence < threshold → deny |
| `CVE-0000-9005--same-family-pair-not-flagged` | cross-family rule honored at every dispatch step |
| `CVE-0000-9006--major-jump-auto-merge` | major-version upstream fix is not auto-merge eligible |
| `CVE-0000-9007--unsigned-replay-critical-file` | signed-manifest must cover every replay-critical file |

### Trivial fixture

`CVE-0000-0000` — the minimum advisory-only fixture (no patch, no reproducer). Acts as the schema-layer smoke test.

---

## `kind_reason` vocabulary

Locked in `policy/bundle-schema.json` as an enum. Reproducing here as documentation for what each value means in practice and which fixture (or real bundle) exercises it.

| `kind_reason` | meaning | example bundle |
|---|---|---|
| `ineligible-no-fix-available` | no upstream fix exists; advisory-only | `CVE-0000-9001--advisory-has-patch` |
| `ineligible-major-version-only` | upstream fix only in a major-version bump; auto-backport refused | `CVE-0000-9006--major-jump-auto-merge` |
| `ineligible-cherry-pick-required` | upstream fix sits behind unrelated commits that can't cleanly cherry-pick | (no live example yet) |
| `ineligible-low-confidence-mapping` | Cartographer CPE/PURL match below threshold | `CVE-0000-9004--low-confidence-auto-merge` |
| `ineligible-no-passthru-tests` | affected attr has no `passthru.tests` → no regression-evidence dimension | (no live example yet) |
| `ineligible-no-vuln-reproducer` | Reproducer refused under rule 3+; no sandbox-positive evidence available | (folds into `cross-family-pair-unavailable` for mruby; future bundles may use this directly) |
| `blast-radius-exceeds-threshold` | reverse-closure > 500 (v0 default) | `CVE-2025-4598--systemd`, `CVE-2025-9230--openssl_3` |
| `major-version-jump-requires-review` | minor-jump fix available but rejected by policy | `CVE-2025-67899--uriparser` |
| `large-sbom-delta` | patched closure diff exceeds threshold (deferred sbom-delta computation) | (no live example yet; sbom-delta deferred to v1.x) |
| `reviewer-verdict-escalate` | Reviewer chose `escalate` over accept/reject | (no live example yet) |
| `cross-family-pair-unavailable` | no model in a different family qualified for the required cross-family role | `CVE-2025-7207--mruby` |

The unused-yet values (5 of 11) are pre-registered slots — adding a real bundle that exercises them does not require a schema change. Adding a NEW reason requires a schema update + DECISIONS entry.

---

## v0 cohort split: model-attested vs sandbox-positive

The 2026-05-14 DECISIONS entry documents a structural property of the v0 corpus: the candidate pool splits cleanly into two **non-overlapping** cohorts along `patch_shape` × `UpstreamRefResolver` verdict.

- **Model-attested cohort** (`patch_shape ∈ {version-bump, mixed}`, ≈ 39 / 51 candidates). UpstreamRefResolver routes to `eligible`; Patcher + Reviewer run end-to-end; the natural disposition is **reviewer-attested auto-merge** (Steward rule 13). The Reproducer cannot ship sandbox-positive evidence here because reconstructing the unpatched src needs a network fetcher.

- **Sandbox-positive cohort** (`patch_shape == overlay`, 11 / 51 candidates). Patches += [./CVE-NNNN.patch] or cherry-picked commits applied as patches — Reproducer can reconstruct unpatched by filtering the overlay out (the libtiff template). But every overlay candidate in the current corpus lacks a release tag containing the fix, so UpstreamRefResolver routes them to `ineligible-cherry-pick-required` → bundle.kind=advisory-only → Reproducer rule 2 refuses. The chain never reaches the Reproducer stage to exercise the sandbox-positive path under model-attested rules.

The two real-CVE sandbox-positive bundles (`libtiff CVE-2024-13978`, `mruby CVE-2025-7207`) bypass this gap by being **deterministic-no-model** — hand-authored resolver inputs + hand-written reproducer.nix. They are evidence that sandbox-positive works on the deterministic path, not that it works on the model-attested path.

**No corpus candidate today hits both paths.** This is by design as of v0; v0.1 design work may relax the resolver (allow overlay-via-fetchpatch as `eligible` when a release tag exists) or the Reproducer parser (carve out hash-pinned FOD lookup), at which point a single-bundle full-path candidate becomes possible.

### Curation filters (post-2026-05-14)

| goal | filter on `eval/candidates.jsonl` |
|---|---|
| Model-attested auto-merge candidate | `axes.patch_shape ∈ {version-bump, mixed}` AND `expected_v0_eligibility == "auto-merge-eligible"`. Skip Reproducer-sandbox expectations; ship via reviewer-attested. |
| Deterministic sandbox-positive candidate | `axes.patch_shape == "overlay"` AND a hand-authored `resolver-input.json` that supplies a synthetic upstream-ref pointing at the fix commit. The libtiff/mruby template. |
| Cross-path candidate (rare, v0.1) | `axes.patch_shape == "overlay"` AND upstream has a release tag containing the fix. None of the current 51 candidates qualify; new harvests should record this. |

### Sandbox-positive PoC suitability filter (post-2026-05-17, F6)

The wget2 cert arc surfaced that `patch_shape` alone is insufficient to predict whether a CVE's PoC will fire in the Nix build sandbox. A CVE's *PoC class* must independently qualify. Codified after F6.

A candidate qualifies as a v0.1 **sandbox-positive anchor** iff its PoC meets ALL four:

1. **Local-file + binary-invocation PoC.** The malicious input is constructible via `pkgs.writeText` / `pkgs.writeScript` / inline binary fixture; the affected code path is reached by passing that file to the affected binary. No network egress required.
2. **No external network dependency.** No "binary fetches attacker-controlled URL", no "DNS lookup resolves to evil host", no "client connects to remote server". The Nix build sandbox is network-isolated by design; any test depending on network is non-portable across the cert workflow.
3. **No daemon / listener requirement.** No "spawn server, client connects". Loopback listeners work technically in the sandbox but add test-side complexity (port-coordination, kill-on-timeout, leak-on-failure) we explicitly avoid at v0.1.
4. **PoC construction depth ≤ model-attestation-budget** (added post-2026-05-17 F8). The PoC must be constructible by a sonnet-class model given the CVE summary + upstream fix commit + a single iteration of the Reproducer prompt, without protocol-level fixture engineering. Concretely: if triggering the bug requires authoring a parser schema, a protocol handshake, a specific memory-layout-sensitive input, or matching a hard-to-discover internal code path, the CVE is not a v0.1 anchor candidate.

The fourth criterion was added after the libtasn1 CVE-2025-13151 anchor attempt (DECISIONS 2026-05-17 post-close). libtasn1 passed criteria 1–3 cleanly but the actual PoC requires constructing an ASN.1 schema that walks the parser to a specific name-stitching call site that overruns a stack buffer by exactly one byte. Surface description "stack-based buffer overflow in `asn1_expand_octet_string` on malformed OCTET STRING input" was misleading: a sonnet-class model interprets that as "feed DER to the parser tool," which doesn't actually exercise the bug. The fourth criterion catches this class.

Qualifying CVE classes: parser crashes on malformed file input, integer-overflow on crafted numeric input, syscall-level boundary violations, memory-safety classes triggered by file-based fuzz inputs, malformed-archive handling, path-traversal where the binary writes the path **directly from input** (not via a fetch step).

Disqualifying CVE classes: HTTP-client CVEs requiring real or simulated remote responses (the wget2 CVE-2025-69194 class), DNS-resolution CVEs, network-protocol parsers consuming network data, server-side CVEs requiring inbound connections. These are valuable to address eventually but are not v0.1-anchor material.

Filter for harvesting:

| signal | check |
|---|---|
| CVE summary uses words like "remote attacker", "via HTTP", "via DNS", "metalink", "URL fetching" | likely disqualifying — confirm before adding to candidate pool |
| CVE summary uses words like "crafted file", "malformed input", "parser", "deserialise", "overflow on file" | likely qualifying — verify PoC shape |
| The upstream fix is in a function reachable from `main()` via a local-file CLI argument | strong qualifying signal |
| The upstream fix is in a network-protocol handler (`http.c`, `dns.c`, `metalink.c`, etc.) | strong disqualifying signal at v0.1 |

For future harvesting passes, this filter goes alongside the patch-shape filter. A candidate qualifies for the v0.1 anchor slot iff it satisfies BOTH (model-attested + version-bump) AND (sandbox-positive PoC suitability — all four criteria).

### Retired v0.1 anchor attempts

Two model-attested candidates have run the chain through the filter and been retired for distinct, codified reasons:

| candidate | failed criterion | new `kind_reason` | what it taught |
|---|---|---|---|
| `CVE-2025-69194--wget2` | #2 (no external network) | `sandbox-poc-requires-network` | F1–F7 contract slice (DECISIONS 2026-05-17). The framework's honesty contract held end-to-end; the sandbox-positive *contract* works, but wget2's metalink CVE needs HTTP. Codified criteria 1–3. |
| `CVE-2025-13151--libtasn1` | #4 (construction depth) | `poc-construction-exceeds-anchor-depth` | F8 (DECISIONS 2026-05-17 post-close). Surface description matched a parser-shaped CVE, but exploitation requires constructing a specific ASN.1 schema that walks the decoder to a 1-byte off-by-one site. Sonnet-class model picked the wrong CLI tool (asn1Parser vs asn1Decoding). Codified criterion 4. |

Each retirement is itself the demonstration: the framework refused to fake a green signal on a candidate the filter passed. The filter is a learned object, not a designed one — it sharpens through honest failures.

---

## Non-Reproducer bundles, explicitly

Pulling the non-Reproducer slice out separately because it's the load-bearing distinction for the maintainer-trust narrative.

Six of the eight real-CVE bundles ship without a working sandbox-positive Reproducer:

- **`mbedtls` / `traefik`**: patch story is self-evident (single fetchpatch, single-hash bump on small packages); Patcher + Reviewer alone are sufficient for auto-merge.
- **`bind` / `uriparser`**: Reproducer refused under v0 rule 3 (silent crash class without public PoC, or sandbox-incompatible network/recursion behaviour). Bundle ships with `reproducer-refusal.json` documenting the refusal.
- **`systemd` / `openssl_3`**: blast-radius downgrades the bundle to `human-review-required` regardless of any Reproducer state; Reproducer not even attempted.

The two with reproducers:

- **`libtiff`**: reproducer.nix authored, SIGNAL verified on Darwin; Linux portability is the open question (DECISIONS 2026-05-12).
- **`mruby`**: reproducer.nix authored hand-on with ASAN; Darwin-validated; Linux ASAN-wiring is the open blocker (DECISIONS 2026-05-12).

Both reproducer-bearing bundles currently ship as `human-review-required` because their Linux-cert axis is incomplete. Once Steward rule 12 (auto-merge requires Linux build.json) clears via the per-bundle `bundle-linux-cert.yml` workflow, libtiff is closest to flipping to auto-merge.

---

## What the corpus is for

Two consumers:

1. **The release/demo path.** A reviewer reading the trace v0.2.0 README wants to inspect 1-2 example bundles to understand what trace produces. The auto-merge candidates (mbedtls, bind, traefik) plus one human-review bundle (systemd) are the canonical demo set.

2. **The future review-panel pilot.** v0's locked plan is a 5-bundle review-panel pilot with ≥3 nixpkgs-literate reviewers (per SPEC §7 open question 5). That panel will sample the corpus — likely 1 from each row of the auto-merge table + 2 from the human-review table. The corpus needs to be diverse enough that the panel sees the contract layer's full surface.

The corpus is not a research result on its own. It's the body of evidence that lets a human evaluate the contract layer.

---

## How to add a bundle to the corpus

Two paths:

1. **Real-CVE bundle from Scout.** Run `trace bundle assemble` against a resolver-input.json (Scout's output for a specific CVE), then `trace bundle finalize --kind <kind> --kind-reason <enum>`. Add a README under `traces/example/<CVE-ID>--<pname>/` documenting what the bundle exercises in the corpus taxonomy. Run the per-bundle Linux-cert workflow if the bundle's eligible for auto-merge.

2. **Synthetic fixture for a Steward rule.** Copy `CVE-0000-0011--full-chain-auto-merge` and mutate exactly one input to violate one Steward rule. Update `expect.json` with the rule_id. Re-run `tests/steward/test_steward.py` to confirm the rule fires.

Either way: add an entry to this document. A bundle that isn't in this taxonomy is a bundle the corpus doesn't claim to demonstrate.
