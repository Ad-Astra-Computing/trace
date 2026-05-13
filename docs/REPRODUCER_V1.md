# Reproducer v1 — contract specification

**Status:** locked. This document defines what `prompts/reproducer.v1.md` will enforce, what the runner will check before write, and what the scorers will measure. The prompt and runner are derived from this spec, not the other way around.

**Supersedes:** SPEC.md was silent on Reproducer's exact output shape. SPEC.md §1.2 still defines Reproducer's *role* (vuln-specific reproduction); this document defines the v1 *contract*.

**Related decisions:**
- 2026-04-28 (b2b3b2c) — Reproducer cross-family-with-Patcher locked.
- 2026-04-27 — Patcher rule 8 (grounded-hash refusal) is the model for refusal-as-correct-output.

---

## 0. Purpose

The Reproducer answers exactly one question per bundle:

> *Does the supplied patch actually fix the supplied CVE on the supplied package, demonstrably, in a self-contained way the Builder can replay?*

Not "does the package build." Not "are the tests we already had still green." Not "is the patch plausible." The Reproducer must produce a **vuln-specific signal** that is present pre-fix and absent post-fix. Anything weaker is a proxy test (§7) or a refusal (§6).

The output is consumed by Builder (which executes the reproducer twice — patched and unpatched) and by Steward (which gates `bundle.kind=auto-merge` on the Reproducer's verdict).

---

## 1. Cross-family rule (recap)

Per the 2026-04-28 lock: the Reproducer model must run in a model family different from the Patcher model family recorded in `replay.json`. Enforcement is in the executor, not the prompt. The model's own `cross-family attestation` line is theatrical and does not contribute to `replay.json.cross_family_rule_honored`.

The default v0 reproducer model is `claude-sonnet-4-6`, which is mechanically distinct from the locked `claude-opus-4-7` patcher.

---

## 2. Inputs

The Reproducer is given the entire post-Patcher bundle. Specifically:

- **`finding.json`** — CVE id, affected attrs, severity, advisory references. Treat as authoritative truth for what bug must be triggered.
- **`upstream-ref.json`** — `current_version`, `target_version`, `upstream_fix_commits[]`, `eligibility.verdict`, plus the prefetched-hashes record. Treat as authoritative truth for what tags / commits define pre-fix and post-fix states.
- **`impact.json`** — informational. Reverse-closure size matters for risk framing in `reproducer-log.txt`'s commentary, not for the test logic itself.
- **`maintainers.json`** — informational.
- **`patch.diff`** — the patch the Reproducer is verifying. Read it to understand what the fix changes.
- **`patch-rationale.md`** — informational. Useful for understanding *why* a particular change fixes the CVE; does NOT ground claims by itself.
- **`package.nix`** — the pre-fix package definition. Used to construct the unpatched derivation.
- **The pinned nixpkgs source tree at `finding.json.nixpkgs_rev`** — used by the runner / Builder, not directly by the model. The Reproducer references attrs by path and produces Nix code that resolves against this tree.

No other inputs. No network. No tools beyond reading the supplied files.

If the Reproducer feels it needs an artifact not in the bundle (e.g., a public PoC repository, an upstream test fixture, a CVE-specific malformed input file), the only correct response is a refusal under §6 — never an invented payload.

---

## 3. Outputs

Exactly three files, in order, separated by file markers (mirroring patcher.v1's strict-output contract):

```
=== BEGIN reproducer.nix ===
<Nix expression>
=== END reproducer.nix ===
=== BEGIN reproducer-log.txt ===
<predicted execution log>
=== END reproducer-log.txt ===
=== BEGIN passthru-tests.json ===
<JSON array>
=== END passthru-tests.json ===
```

No prose before, between, or after. Anything outside the file blocks is a parser refusal (`ReproducerOutputMalformed`) at the runner boundary, mirroring the Patcher contract enforcement.

### 3.1. `reproducer.nix`

A Nix expression that, when evaluated by Builder, produces two derivations:

```nix
{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.<attr>.overrideAttrs (old: {
    # restore pre-fix state
  });
  patched = pkgs.<attr>;  # already patched in this bundle's nixpkgs tree
in
{
  inherit unpatched patched;

  # The vuln-specific test. Must produce stdout that contains a
  # signal substring documented in reproducer-log.txt.
  test = pkgs.runCommand "repro-${finding.cve_id}" { } ''
    set -e
    # invoke <attr>'s vulnerable surface
    # capture output
    # assert presence (in unpatched build) or absence (in patched build) of the signal
  '';
}
```

Locked properties:

- Top-level expression is a function `{ pkgs ? import <nixpkgs> { } }: { ... }`.
- Returns an attrset with at least three attributes: `unpatched`, `patched`, `test`.
- `test` is a single derivation that exercises the vuln. **It MUST NOT just rebuild the package.** A test whose only assertion is "it builds" is a proxy test (§7) and must be labeled as such.
- The test's exercise surface MUST be the **CVE-class behaviour itself** — the function call, syscall, parsing path, signal handler, etc. that the CVE describes. Generic build success is forbidden as the sole assertion.
- The signal that distinguishes pre-fix from post-fix MUST be a **textual substring** of the test's stdout / stderr that the model also names verbatim in `reproducer-log.txt`. Builder uses the substring to compute the verdict mechanically; the model's claim alone is not the verdict.
- No `import` of files outside the bundle. No `fetchurl` / `fetchzip` / `fetchFromGitHub` calls (the bundle's existing prefetched src is the only source). If the test needs a fixture, the fixture is inlined as a Nix `pkgs.writeText` / `pkgs.writeScript`.

### 3.2. `reproducer-log.txt`

The model's predicted execution log. Two sections, separated by line markers:

```
=== unpatched ===
<predicted stdout/stderr from running `test` against the unpatched derivation>
SIGNAL_UNPATCHED: <verbatim substring that proves the vuln triggered>
EXIT: <integer exit code>

=== patched ===
<predicted stdout/stderr from running `test` against the patched derivation>
SIGNAL_PATCHED: <verbatim substring that demonstrates the vuln no longer triggers>
EXIT: <integer exit code>
```

The two signals are **paired and asymmetric**: `SIGNAL_UNPATCHED` is a substring whose **presence** in the unpatched run proves the vuln triggered. `SIGNAL_PATCHED` is a substring whose **presence** in the patched run proves the vuln did not trigger. Both must be substrings the test produces explicitly (e.g., a `printf "vuln-triggered: ..."` line on the unpatched path and a `printf "rejected-malformed-input: ..."` line on the patched path). Builder verifies presence on both sides — the test's own output names what it observed, and the model commits in advance to what those names will be.

Locked properties:

- `SIGNAL_UNPATCHED` MUST appear in the actual unpatched run's output. Builder verifies; absence is a scorer failure (`repro-unpatched-fails: 0.0`).
- `SIGNAL_PATCHED` MUST appear in the actual patched run's output. Builder verifies; absence is a scorer failure (`repro-patched-passes: 0.0`).
- **Length bounds.** Each signal substring MUST be ≥ 24 characters and ≤ 200 characters. Shorter than 24 chars is gameable noise (`error`, `failed`, `denied`, `assertion failure`); longer than 200 chars is brittle (whitespace drift, locale-dependent formatting). Bounds enforced by the runner before write.
- **Semantic specificity.** Each signal MUST be semantically tied to the **CVE-class outcome**, not to generic build / runtime tokens. The runner rejects (parser refusal, no write) any signal whose entire content matches a generic-token pattern. The forbidden generic-token list, locked here:
  - `error`, `error:`, `failed`, `failure`, `assertion failed`, `aborted`, `core dumped`
  - `success`, `ok`, `passed`, `done`, `complete`
  - `exit code 0`, `exit code 1`, `exit status 0`, `exit status 1`
  - the empty string
  - any substring composed only of whitespace and one of the tokens above

  These rules are floor checks. The `repro-signal-specificity` scorer (advisory, §9) goes further and downgrades signals whose body is too generic relative to the CVE description.

- **Distinct signals.** `SIGNAL_UNPATCHED` and `SIGNAL_PATCHED` must NOT be substrings of each other. Identical signals or substring-prefix relationships defeat the discrimination contract.
- The two `EXIT:` lines record predicted exit codes. Builder records actual exit codes; mismatch is a scorer signal but not a refusal trigger (the model is allowed to be wrong about the exit code; the signal-substring presence is the real oracle).
- The model is permitted to write a brief one-paragraph commentary above each `=== unpatched ===` / `=== patched ===` marker, explaining what the test does. Beyond that, no prose; no rationale section like patch-rationale's five headings.
- The signal-substring CHOICE matters. The model should choose the most CVE-specific text it can — function name + observed misbehaviour, parser-rejection message naming the malformed input class, sandboxed kernel oops fragment, etc. The `repro-signal-specificity` scorer (§9) is advisory but its trends are reported in the cohort aggregate.

### 3.3. `passthru-tests.json`

A JSON array enumerating the `passthru.tests` and `nixosTests` attrs that exercise the affected attr at the bundle's `nixpkgs_rev`. The Reproducer enumerates; it does NOT generate.

```json
[
  { "name": "passthru.tests.basic", "drv_path": "/nix/store/...-systemd-passthru-test-basic.drv", "kind": "passthru.tests" },
  { "name": "nixosTests.systemd-coredump", "drv_path": "/nix/store/...-systemd-coredump-test.drv", "kind": "nixosTests" }
]
```

Locked properties:

- Empty array `[]` is valid (the package may have no passthru tests).
- Each entry has exactly three keys: `name`, `drv_path`, `kind`.
- `kind` is one of `passthru.tests`, `nixosTests`. Other test idioms are out of scope for v0.
- The model is NOT responsible for running these tests — Builder is. The model's job here is enumeration, so Steward can record regression-coverage independently of the Reproducer's CVE-specific test.
- If the model cannot determine `drv_path` (impossible without nix-build), it MAY emit `"drv_path": null`. Builder fills these in at execution time. Other fields must be present.

---

## 4. Success criteria

A bundle's Reproducer output is **well-formed** for v0 when ALL of the following hold:

1. The three files parse and validate against the §3 shape, including the `SIGNAL_UNPATCHED` / `SIGNAL_PATCHED` length bounds, semantic-specificity floor checks, and distinct-signals rule.
2. `reproducer.nix` evaluates without error against the bundle's pinned nixpkgs (Builder's job to verify).
3. The `test` derivation runs to completion in BOTH the unpatched and patched paths (Builder's job to verify).
4. The unpatched run's stdout/stderr contains the `SIGNAL_UNPATCHED` substring named in `reproducer-log.txt`.
5. The patched run's stdout/stderr contains the `SIGNAL_PATCHED` substring named in `reproducer-log.txt`.
6. The `passthru-tests.json` enumeration is consistent with the actual passthru.tests / nixosTests defined for the affected attr at `nixpkgs_rev` (Builder cross-checks).

The first axis is a **model-output well-formedness** check (the runner verifies §3.1–§3.3 shape before write). The remaining axes are **execution checks** that Builder runs and records into `build.json`. Reproducer scoring (§9) reflects both layers.

### 4.1. Platform requirement (v0.3, locked 2026-05-12)

Items 3–5 above are platform-coupled in a way the original v0 contract left implicit. v0.3 makes it explicit: **the `build.json` that the scorers consume must have been produced on `x86_64-linux`**. nixpkgs's canonical CI platform is `x86_64-linux`; a SIGNAL substring that fires on `darwin-aarch64` but not on Linux is evidence the test exercises a platform-specific code path, not the CVE-class behaviour. The empirical motivator: libtiff CVE-2024-13978's PoC TIFF was Darwin-validated; on Linux the crafted bits/sample is rejected by an earlier `Fax3SetupState` validation before reaching the vulnerable `memset(NULL, 0, ...)` site, so `fax2ps` exits 0 with a warning instead of SIGSEGV. See `docs/DECISIONS.md` (2026-05-12 entry on Linux Builder infrastructure + corpus-expansion findings).

Operational support:

- **Steward rule 12** (`policy/steward.rego`): denies `bundle.kind=auto-merge` when `build.json.host.system != "x86_64-linux"`. A bundle authored on Darwin must be re-built on Linux before it can claim auto-merge eligibility.
- **Per-bundle Linux-cert workflow** (`.github/workflows/bundle-linux-cert.yml`): parameterized over `BUNDLE_DIR_NAME`. Manual dispatch produces a Linux-attested `build.json` for any bundle.
- **Darwin-side reproduction remains permitted and useful** for authorship + initial validation. It just isn't sufficient for the auto-merge gate.

Bundles whose PoC is intrinsically non-Linux-portable (e.g., macOS-specific syscalls) can still ship — they downgrade to `bundle.kind=advisory-only` or `human-review-required`, and the Reproducer evidence is human-judged rather than auto-merged. The contract here is about what counts as automation-ready evidence on the canonical platform, not about disqualifying non-Linux research entirely.

### 4.2. Builder-knob escape hatches (v0.3, locked 2026-05-12)

Some packages have slow `doCheck` phases that exceed the Builder's per-build timeout despite the underlying derivation being fine. The reproducer-runs cover the CVE-class regression dimension; `patched_build` is a sanity build. To prevent slow check suites from blowing the timeout, bundles may opt in to `reproducer-instrumentation.json` knobs that affect Builder behaviour only:

```json
{ "schema_version": "1.0.0", "asan": false, "disable_doCheck": true }
```

- `asan` (v0.1): instruments the reproducer-run phases with AddressSanitizer (BUILDER_V1 §2.6).
- `disable_doCheck` (v0.3): the patched-build sanity phase uses `(import ./. {}).<attr>.overrideAttrs (old: { doCheck = false; })` instead of the raw attr. Reproducer-runs are unaffected — their derivations are author-controlled.

Both knobs are data-config only. Reproducer and Patcher do not see this file; the model commits to the SIGNAL substring contract independent of Builder's wiring.

---

## 5. Failure criteria

A Reproducer output is a **failure** (not a refusal — refusal is §6) when ANY of the following hold:

- The output parses as the §3 shape but the unpatched run's actual stdout/stderr does NOT contain the named `SIGNAL_UNPATCHED` substring → the test does not exercise the vuln.
- The patched run's actual stdout/stderr does NOT contain the named `SIGNAL_PATCHED` substring → the patch did not produce the expected fixed-state evidence, OR the test failed before reaching the assertion.
- `reproducer.nix` evaluates but raises at `test` execution time on the unpatched path due to setup error (missing dependency, malformed expression body, etc.).
- Both signals appear in BOTH runs — i.e., the test does not discriminate. This is the most common failure mode and the most insidious: the test "looks vuln-specific" but actually only checks something the patch didn't change.

Failure cases are recorded in `build.json` with an explicit reason. Bundles with failed reproducers are NOT eligible for `bundle.kind=auto-merge`. They downgrade to `human-review-required`. They are not advisory-only — the patch may still be correct; only the Reproducer's verification path is broken.

---

## 6. Refusal conditions

The Reproducer MUST refuse, with a structured refusal block, when ANY of the following hold:

1. **No patch to reproduce against.** `patch.diff` is missing, empty, or itself a refusal block (the Patcher refused under one of its own rules).
2. **Bundle is advisory-only.** `bundle.json.kind=advisory-only` OR `upstream-ref.json.eligibility.verdict` starts with `ineligible-`. Reproducer must not generate test code for advisory-only bundles. Mirrors Patcher rule 3.
3. **Vuln class is not locally-reproducible.** The CVE describes a behaviour that cannot be triggered inside Nix's build sandbox: requires kernel privilege escalation, requires network access (sandbox is offline), requires specific hardware, requires a multi-process race that the sandbox cannot reliably arrange. The refusal must cite the specific blocker.
4. **No public PoC and the vuln class is opaque.** When the CVE description names "out-of-bounds read in function X" but the Reproducer cannot determine what input triggers X, AND no advisory or upstream-fix-commit message names a triggering input. The refusal must cite which artifact the Reproducer expected to provide the trigger.
5. **The CVE is a social-engineering / configuration / supply-chain class** that does not admit a self-contained mechanical test. E.g., "users may be tricked into copying a malicious config." The refusal must cite the CVE's class.
6. **The patch's claimed fix scope does not match the CVE description.** The patch addresses a different surface than `finding.json` describes. (This is a real signal — the Reviewer should also catch it — but Reproducer refuses rather than writing a test it cannot anchor.)
7. **`upstream-ref.json` is missing OR `eligibility.verdict` is absent.** Mirrors Patcher rule 1+2.

The refusal block:

```
=== BEGIN refusal ===
rule: <number>
reason: <one-line reason citing the specific input field or vuln class>
=== END refusal ===
```

No reproducer.nix. No log. No passthru-tests.json. Steward routes the bundle to `human-review-required` with `kind_reason: reproducer-refused-rule-<n>`.

**Refusal is not failure.** Refusal is the correct output when the inputs do not authorise a test. Do not fabricate a test "to be safe." Do not write a build-only proxy "as a placeholder." Refuse.

---

## 7. Proxy tests (the bounded compromise)

Some CVEs admit no full-chain reproducer in the sandbox but DO admit a meaningful constrained test: "verify the patched function rejects malformed input X" rather than "verify the full attack chain." Proxy tests are allowed in v0 but **discouraged**: refusal under §6 is the preferred output when a full reproducer is infeasible. A proxy is acceptable ONLY when it provides **meaningful constrained evidence** of the fix, not as a convenience to avoid the harder refusal path.

The contract treats proxies as a narrow, well-labeled compromise. The reproducer.nix MUST set the following attributes on the `test` derivation:

```nix
test = pkgs.runCommand "..." { } ''
  ...
'' // {
  meta = {
    proxy = true;
    proxy_reason = "<one of the locked enum values below>";
    why_not_full_repro = "<one-paragraph explanation>";
    expected_limitations = "<one-paragraph explanation>";
  };
};
```

Locked properties:

- **`meta.proxy = true`** — required boolean. Single source of truth that this is a proxy, not a full reproducer.
- **`meta.proxy_reason`** — required, MUST be one of the locked enum values:
  - `sandbox-cannot-trigger` — the full chain requires capabilities the build sandbox forbids (kernel privilege, network, hardware feature, multi-process timing).
  - `chain-requires-public-poc` — a full chain exists but requires a payload only published in an external PoC repo the bundle does not carry; only the post-patch rejection path is locally verifiable.
  - `pre-fix-build-uncrashable-in-sandbox` — the unpatched code crashes the sandbox itself or the host (kernel oops, heap corruption out-of-process); only the patched-rejection path is testable.
  - `attack-surface-not-locally-instrumentable` — the vuln triggers via a system service / IPC surface that cannot be brought up inside `runCommand`. Localhost-only proxy of the same parser/handler is feasible.
  - `cve-class-needs-fixture-corpus` — the vuln class (parser bug, codec, regex backtracking) needs a fixture set the bundle does not carry; a representative sub-fixture proves the patched-state behaviour.

  Any other reason is NOT a permitted proxy under v1. If none of these enum values apply, the correct output is a §6 refusal.

- **`meta.why_not_full_repro`** — required, one-paragraph string. Names the specific blocker, citing the bundle artifact, vuln class, or sandbox limitation. Generic restatement of the enum value is insufficient; the explanation must be specific to THIS CVE.
- **`meta.expected_limitations`** — required, one-paragraph string. Names what the proxy DOES NOT prove. E.g., "this proxy verifies the parser now rejects the malformed length-prefix; it does not verify the integer-overflow path the unpatched parser would have hit downstream — that path is unreachable in any sandbox we can construct."

The reproducer-log.txt MUST include a third section `=== proxy ===` after `=== patched ===`, restating `proxy_reason`, `why_not_full_repro`, and `expected_limitations` as plain text so they survive in a non-Nix-eval context (Reviewer reads the log; Steward parses the log).

**Steward gate.**

- Bundles with `meta.proxy = true` are NOT eligible for `bundle.kind=auto-merge`. They downgrade to `human-review-required` with `kind_reason: reproducer-is-proxy`.
- The Steward enforces this downgrade by reading `meta.proxy` from `reproducer.nix` (or from the proxy section of `reproducer-log.txt` as a fallback). The Reproducer's claim alone does not gate the bundle; Steward's mechanical check does.
- A proxy reproducer that fails to populate any of the four required `meta` fields is treated as a §5 failure (malformed proxy claim), not a valid proxy.

**Reviewer expectation.** The Reviewer is required to read the proxy section, weigh `expected_limitations` against the CVE description, and either accept (the proxy is a meaningful constrained test for this CVE class) or reject (the proxy is too narrow to support the patch's claim). Proxy bundles have a heightened Reviewer-engagement burden documented here so it surfaces in reviewer.v1's next additive update.

**Refusal preferred over weak proxy.**

- Generic build-passes-as-proxy is NOT acceptable; it is a §5 failure case.
- A proxy whose `expected_limitations` reads "this test is essentially equivalent to a build-pass check" is NOT acceptable; refuse under §6.5 instead.
- A proxy whose `proxy_reason` does not match any of the locked enum values is NOT acceptable; refuse under §6.5 instead.
- The model SHOULD prefer refusal when the only available proxy would carry an `expected_limitations` paragraph that subsumes the actual fix. The contract says: a refusal that names the gap is more useful than a proxy that does not honestly cover it.

**Reporting.**

- The cohort aggregator (forthcoming) tracks `proxy_rate` (fraction of reproducers labeled proxy) as a non-advisory metric. Trend over time is the signal: a rising proxy_rate without a corresponding rise in CVE-class diversity is evidence of contract drift. The acceptable proxy_rate floor is not locked here; it will be revisited once a baseline run produces a proxy_rate number across the corpus.
- Per-bundle `proxy_reason` distribution is recorded in the aggregator's provenance list so future analysis can see which sandbox-limitation classes drive proxies.

---

## 8. Replay / provenance shape

The reproducer invocation in `replay.json` mirrors patcher / reviewer shape with one addition. New fields locked here for the runner to populate:

```json
{
  "invocation_id": "<uuid>",
  "role": "reproducer",
  "started_at": "...",
  "ended_at": "...",
  "model": { "family": "...", "vendor": "...", "model_id": "...", "version": "...", "sampling": {...} },
  "prompt": { "path": "prompts/reproducer.v1.md", "sha256": "..." },
  "inputs": [
    { "path": "finding.json",         "sha256": "..." },
    { "path": "upstream-ref.json",    "sha256": "..." },
    { "path": "impact.json",          "sha256": "..." },
    { "path": "maintainers.json",     "sha256": "..." },
    { "path": "patch.diff",           "sha256": "..." },
    { "path": "patch-rationale.md",   "sha256": "..." },
    { "path": "package.nix",          "sha256": "..." }
  ],
  "outputs": [
    { "path": "reproducer.nix",       "sha256": "..." },
    { "path": "reproducer-log.txt",   "sha256": "..." },
    { "path": "passthru-tests.json",  "sha256": "..." }
  ],
  "patcher_invocation_id": "<the patcher invocation this reproducer is verifying>",
  "patcher_family_recorded": "<family resolved by executor from the patcher invocation>",
  "cross_family_rule_honored": true,
  "rng_seed": null,
  "validators_passed": ["schema-valid-output"],
  "network_policy_applied": "none"
}
```

`patcher_invocation_id` and `patcher_family_recorded` are new fields. They make the cross-family pairing auditable from the replay record alone, the same way the existing reviewer invocation surfaces the same metadata.

A refusal is recorded with `validators_passed: ["refusal-shape"]`, `outputs: [{ "path": "reproducer-refusal.json", "sha256": "..." }]`, and the structured refusal body persisted as `reproducer-refusal.json` in the bundle (mirroring Patcher's `refusal.json`).

---

## 9. Scorers (forthcoming, locked here)

The v0 Reproducer scorer set, locked alongside this contract:

| scorer | applies | advisory | what it measures |
|---|---|---|---|
| `repro-schema-valid` | parsed | no | reproducer.nix parses as Nix; reproducer-log.txt has the two required sections (or three if proxy); SIGNAL_UNPATCHED + SIGNAL_PATCHED satisfy length bounds, generic-token floor, and distinct-signals rule; passthru-tests.json is a JSON array of well-shaped entries; if proxy, all four `meta.proxy*` fields present and `proxy_reason` matches the locked enum. Pre-Builder. |
| `repro-unpatched-fails` | parsed AND build.json present AND not proxy | no | Builder ran the test against the unpatched path; the SIGNAL_UNPATCHED substring appeared in stdout/stderr. |
| `repro-patched-passes` | parsed AND build.json present | no | Builder ran the test against the patched path; the SIGNAL_PATCHED substring appeared in stdout/stderr. Applies even for proxy reproducers (the proxy still has to demonstrate its constrained patched-state evidence). |
| `repro-passthru-recorded` | parsed | no | passthru-tests.json contains every passthru.tests / nixosTests attr defined for the affected attr at nixpkgs_rev. Builder enumerates ground truth; scorer compares. Empty-array is valid only if the package truly has no such tests. |
| `repro-signal-specificity` | parsed AND build.json present | yes (advisory) | Both signals are sufficiently CVE-specific. Heuristic stack: length ≥ 24 (already a §3.2 floor — scorer raises the floor to ≥ 32 for advisory), at least one signal includes a word from `finding.json.summary` of length ≥ 5 chars OR a function/symbol name from any `upstream_fix_commits[].message`, neither signal matches an extended generic-token pattern. Advisory because heuristic, not gating. |

`repro-unpatched-fails` and `repro-patched-passes` are the load-bearing pair. For non-proxy bundles, both must score 1.0 for the bundle to be auto-merge-eligible. Steward consumes these directly; Reviewer is expected to read them as evidence in its accept/reject.

For proxy reproducers (§7):
- `repro-unpatched-fails` records `applies=false` with a notes string `"proxy test (proxy_reason=<enum>); unpatched-path evidence is by design out of scope"`.
- `repro-patched-passes` still applies and is non-advisory: a proxy that cannot demonstrate even its constrained patched-state evidence is a §5 failure.
- `repro-schema-valid` enforces the four required `meta.proxy*` fields. A proxy that omits any of them scores 0.0 here.

The aggregator (forthcoming, mirroring `agents/scorers/aggregator.py` and `agents/scorers/reviewer_aggregator.py`) will surface:

- `reproducer_well_formed_rate` (repro-schema-valid mean)
- `vuln_signal_recovered_rate` (repro-unpatched-fails AND repro-patched-passes both 1.0, per non-proxy bundle)
- `proxy_patched_passes_rate` (repro-patched-passes 1.0 across proxy bundles only — measures whether proxies, when used, at least carry their narrower claim)
- `passthru_coverage_mean` (repro-passthru-recorded mean)
- `proxy_rate` (fraction of reproducers labeled proxy; non-advisory; trend over time is the contract-drift signal)
- `proxy_reason_distribution` (per-`proxy_reason` counts; informational)
- `refusal_rate` (fraction of reproducer-refusals)
- `signal_specificity_mean` (advisory)

---

## 10. Open questions parked

These are NOT blockers for the v1 contract; they're noted for future iteration.

1. **NixOS test integration.** Some CVEs are best reproduced via `nixosTest` (full VM). v1 keeps reproducer.nix as a single `runCommand` derivation. NixOS-test-shaped reproducers are deferred.
2. **Multi-attr CVEs.** v1 assumes one affected attr per bundle. CVEs that span multiple attrs (e.g., systemd + udev) need either one reproducer that exercises both or a per-attr reproducer set. v1 punts; the corpus has no such cases yet.
3. **Sandbox network policy.** v1 forbids network in reproducer.nix. Some CVEs (TLS, DNS, HTTP parsing) are most cleanly reproduced with a tiny in-sandbox client + server. v1 routes those to proxy or refusal; v2 may carve out a localhost-only network exception.
4. **Reviewer reading reproducer artifacts.** Currently the Reviewer's input set does NOT include reproducer.nix / reproducer-log.txt. This will change once Reproducer is wired; the Reviewer should be able to cite the SIGNAL substring and the test's discriminating logic. The reviewer.v1 prompt will need an additive update (NOT a contract change) when this lands.

---

## 11. What this document does not cover

- The exact wording of `prompts/reproducer.v1.md`. That's step 3 of the arc, derived from this contract.
- The runner shape (`agents/reproducer/runner.py`). That's step 4.
- The scorer implementation details. The scorer set is locked here; the implementations come in step 5.
- Builder's nix-build invocation strategy. Reproducer hands Builder a Nix expression; Builder decides how to evaluate it.
