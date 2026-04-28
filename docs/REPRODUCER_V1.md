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
SIGNAL: <verbatim substring that proves the vuln triggered>
EXIT: <integer exit code>

=== patched ===
<predicted stdout/stderr from running `test` against the patched derivation>
SIGNAL_ABSENT: <verbatim substring; describes what is NOT in the patched output>
EXIT: <integer exit code>
```

Locked properties:

- The `SIGNAL:` line in `=== unpatched ===` names a substring that MUST appear in the actual unpatched run's output (verified by Builder).
- The `SIGNAL_ABSENT:` line in `=== patched ===` names the same kind of substring but asserts it does NOT appear in the patched run's output.
- The two `EXIT:` lines record predicted exit codes. Builder records actual exit codes; mismatch is a scorer signal but not a refusal trigger (the model is allowed to be wrong about the exit code; the signal-substring presence/absence is the real oracle).
- The model is permitted to write a brief one-paragraph commentary above each `=== unpatched ===` / `=== patched ===` marker, explaining what the test does. Beyond that, no prose; no rationale section like patch-rationale's five headings.
- The signal-substring CHOICE matters. A signal that's also present in unrelated builds is a weak oracle. The model should choose the most CVE-specific substring it can — function name + error class, kernel oops trace fragment, parser-rejection message, etc.

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

1. The three files parse and validate against the §3 shape.
2. `reproducer.nix` evaluates without error against the bundle's pinned nixpkgs (Builder's job to verify).
3. The `test` derivation runs to completion in BOTH the unpatched and patched paths (Builder's job to verify).
4. The unpatched run's stdout/stderr contains the `SIGNAL:` substring named in `reproducer-log.txt`.
5. The patched run's stdout/stderr does NOT contain the `SIGNAL_ABSENT:` substring named in `reproducer-log.txt`.
6. The `passthru-tests.json` enumeration is consistent with the actual passthru.tests / nixosTests defined for the affected attr at `nixpkgs_rev` (Builder cross-checks).

The first axis is a **model-output well-formedness** check (the runner verifies §3.1–§3.3 shape before write). The remaining axes are **execution checks** that Builder runs and records into `build.json`. Reproducer scoring (§9) reflects both layers.

---

## 5. Failure criteria

A Reproducer output is a **failure** (not a refusal — refusal is §6) when ANY of the following hold:

- The output parses as the §3 shape but the unpatched run's actual stdout/stderr does NOT contain the named `SIGNAL:` substring → the test does not exercise the vuln.
- The patched run's actual stdout/stderr DOES contain the named `SIGNAL_ABSENT:` substring → the patch does not actually fix the CVE, OR the signal is not specific enough.
- `reproducer.nix` evaluates but raises at `test` execution time on the unpatched path due to setup error (missing dependency, malformed expression body, etc.).
- The `test` derivation passes against BOTH unpatched AND patched paths — i.e., the test does not discriminate. This is the most common failure mode and the most insidious: the test "looks vuln-specific" but actually only checks something the patch didn't change.

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

Sometimes a CVE admits no full-chain reproducer in the sandbox but DOES admit a meaningful proxy: "verify the patched function rejects malformed input X" rather than "verify the full attack chain." Proxy tests are allowed in v0, with locked constraints:

- The reproducer.nix MUST set a top-level attribute `meta.proxy = true;` on the `test` derivation.
- The reproducer-log.txt MUST include a third section `=== proxy ===` explaining: (a) why the full reproducer is infeasible, (b) what the proxy actually verifies, (c) what gap the proxy leaves uncovered.
- Bundles with `proxy: true` reproducers are NOT eligible for `bundle.kind=auto-merge`. They downgrade to `human-review-required` with `kind_reason: reproducer-is-proxy`.
- The Steward gate enforces this downgrade; the Reproducer's claim alone does not.
- The Reviewer is then expected to weigh the proxy's specificity in its accept/reject decision.

Proxy is the SECOND-best output. Refusal under §6 is acceptable when even a proxy is not feasible. Generic build-passes-as-proxy is NOT acceptable; it is a §5 failure case.

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
| `repro-schema-valid` | parsed | no | reproducer.nix parses as Nix; reproducer-log.txt has the two required sections (or three if proxy); passthru-tests.json is a JSON array of well-shaped entries. Pre-Builder. |
| `repro-unpatched-fails` | parsed AND build.json present | no | Builder ran the test against the unpatched path; the named SIGNAL substring appeared in the output; exit code is non-zero or signal is on stderr (per the test's own contract). |
| `repro-patched-passes` | parsed AND build.json present | no | Builder ran the test against the patched path; the named SIGNAL_ABSENT substring did NOT appear; exit is whatever the test claims. |
| `repro-passthru-recorded` | parsed | no | passthru-tests.json contains every passthru.tests / nixosTests attr defined for the affected attr at nixpkgs_rev. Builder enumerates ground truth; scorer compares. Empty-array is valid only if the package truly has no such tests. |
| `repro-signal-specificity` | parsed AND build.json present | yes (advisory) | The named SIGNAL substring is sufficiently CVE-specific. Heuristic: substring length ≥ 16 chars AND substring includes a word from the CVE description AND substring is not a generic build-system token (`error:`, `failed`, `assertion`). Advisory because heuristic, not gating. |

`repro-unpatched-fails` and `repro-patched-passes` are the load-bearing pair. Both must score 1.0 for the bundle to be auto-merge-eligible. Steward consumes these directly; Reviewer is expected to read them as evidence in its accept/reject.

A proxy reproducer (§7) automatically scores `repro-unpatched-fails: applies=false, advisory note: proxy test, see meta.proxy`. Proxy bundles are gated downstream regardless of scorer outcome.

The aggregator (forthcoming, mirroring `agents/scorers/aggregator.py` and `agents/scorers/reviewer_aggregator.py`) will surface:

- `reproducer_well_formed_rate` (repro-schema-valid mean)
- `vuln_signal_recovered_rate` (repro-unpatched-fails AND repro-patched-passes both 1.0, per bundle)
- `passthru_coverage_mean` (repro-passthru-recorded mean)
- `proxy_rate` (fraction of reproducers labeled proxy)
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
