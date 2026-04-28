# Builder v1 — contract specification

**Status:** locked. This document defines what `agents/builder/` will produce, what the runner will check, and what `build.json` carries. The deterministic Builder dispatcher is derived from this spec, not the other way around.

**Supersedes:** SPEC.md §1.2 names Builder ("driving Hydra-style rebuild of the impacted closure"). `policy/bundle-schema.json` already requires `build.json` in every dispatchable bundle. This document fills in the contract those references presuppose.

**Related decisions:**
- `docs/REPRODUCER_V1.md` §9 — the reproducer scorers already consume `build.json.unpatched.stdout_stderr`, `build.json.patched.stdout_stderr`, `build.json.passthru_tests_ground_truth`. The schema in §3 of this document codifies what those scorers expect.
- `prompts/patcher.v1.md` — the patch.diff Builder applies is constrained to single-attr scope.
- 2026-04-28 (b2b3b2c) — Reproducer cross-family rule. Builder is deterministic (no model call); cross-family does not apply.

---

## 0. Purpose

Builder answers two mechanical questions per bundle, in order:

> 1. **Does the supplied `patch.diff` apply cleanly and produce a buildable derivation against the pinned `nixpkgs_rev`?**
> 2. **When the supplied `reproducer.nix` is evaluated against the pre-fix and post-fix builds, what does the test actually emit?**

Builder is **deterministic policy**. It is NOT a model. It is a structured wrapper around `nix-build` (and a small fixed set of helpers) that records what happened in a replay-safe form. The wrapper has no judgment of its own — it executes, captures, and reports.

---

## 1. Inputs

Builder consumes a finalized bundle directory containing:

- `bundle.json`, `finding.json`, `upstream-ref.json`, `impact.json`, `maintainers.json` (informational)
- `package.nix` — the **pre-fix** package definition
- `patch.diff` — the patch produced by Patcher
- `reproducer.nix` — the test produced by Reproducer (or absent on Reproducer-refused bundles)
- `replay.json` — top-level provenance manifest
- The pinned `finding.json.nixpkgs_rev` is the resolution context (Builder fetches or uses an already-fetched checkout of nixpkgs at this revision)

If `patch.diff` is absent (Patcher refused), Builder writes `build.json` with `dispatch_outcome: refused-no-patch` and exits cleanly. The reproducer-side fields are populated only when `reproducer.nix` is also present.

If `reproducer.nix` is absent (Reproducer refused), Builder still attempts the patched-package build sanity check and records the result; the reproducer-side fields in `build.json` carry `applied: false` with the relevant refusal reference.

---

## 2. Operations

In order of execution. Each operation either succeeds (records its outcome) or fails (records a structured failure record in build.json AND stops subsequent operations that depend on it).

### 2.1. patch-apply

- Apply `patch.diff` to `package.nix` in-place under a working copy of nixpkgs at `nixpkgs_rev`.
- Verify with `git apply --check` first; only commit the working-tree mutation when the dry-run passes.
- Records: applied (bool), `git apply` exit code, the diff's reported file paths, the working-copy commit sha after apply.
- Failure halts §2.2 and §2.3.

### 2.2. patched-build

- `nix-build --no-out-link -A <attr>` against the patched checkout, with `<attr>` being the affected attr from `finding.json.affected[0].attr_path`.
- Captures: build outcome (succeeded/failed), exit code, last 64 KiB of combined stdout+stderr (full log persisted to a separate sidecar artifact `build.log` if it exceeds the inline cap), build time in seconds, derived store path on success, derivation path always.
- Failure does NOT halt §2.3 — the reproducer build may still produce useful negative evidence (the reproducer evaluates `pkgs.<attr>` which itself depends on the patched build, so a patched-build failure usually cascades, but the reproducer's eval of `unpatched` is unaffected and worth recording).

### 2.3. reproducer-runs

For each of `unpatched` and `patched`:

- `nix-build --no-out-link -A <repro_attr>.test reproducer.nix` against the appropriate context. The unpatched context uses the pre-patch nixpkgs checkout; the patched context uses the post-patch checkout.
- Captures: exit code, last 64 KiB of combined stdout+stderr, build time, store path on success.
- Records both runs unconditionally; the reproducer's signal-substring oracle (per `docs/REPRODUCER_V1.md` §3.2) is then a downstream scorer concern.
- For proxy reproducers (`meta.proxy = true` per Reproducer §7), Builder still runs both contexts — proxies ARE expected to demonstrate their narrower patched-state evidence, and the unpatched-side run records "no specific evidence" rather than skipping.

### 2.4. passthru-tests-enumeration

- Evaluate `nix eval --json '<nixpkgs>#<attr>.passthru.tests'` and `<nixpkgs>#nixosTests` filtered to those that reference `<attr>` (heuristic: their drv name or attr path mentions the package name).
- Records: list of `{ name, drv_path, kind }` entries — the **ground truth** the reproducer's `passthru-tests.json` is checked against.
- Failure records an empty list with a structured reason; the `repro-passthru-recorded` scorer applies=False against an unenumerable bundle.

### 2.5. sbom-delta (deferred to v1.x)

The bundle schema reserves `sbom-delta.json`. v1 Builder does NOT compute it. A future Builder iteration may diff the patched closure against the pre-patch closure and record direct/transitive package additions and removals; for v0 the field is empty.

---

## 3. Output: `build.json`

A single JSON document at the bundle root. Locked schema (the reproducer scorers in `agents/scorers/reproducer_scorers.py` already consume the `unpatched`, `patched`, and `passthru_tests_ground_truth` fields shown here):

```json
{
  "schema_version": "1.0.0",
  "cve_id": "CVE-2026-25949",
  "bundle_id": "366c393b1b1f310b",
  "nixpkgs_rev": "adfe0268d8b621c68f0b060fc2e801b5196b5f6a",
  "builder_id": "trace-builder-v0.1.0",
  "host": {
    "system": "x86_64-linux",
    "nix_version": "2.33.3",
    "tool_version": "trace-cli/0.0.0"
  },
  "started_at": "2026-04-28T03:00:00Z",
  "ended_at":   "2026-04-28T03:14:22Z",

  "patch_apply": {
    "applied": true,
    "git_apply_exit_code": 0,
    "files_changed": ["pkgs/os-specific/linux/systemd/default.nix"],
    "post_apply_sha": "..."
  },

  "patched_build": {
    "applied": true,
    "outcome": "succeeded",
    "exit_code": 0,
    "drv_path": "/nix/store/....drv",
    "out_path": "/nix/store/....-systemd-257.6",
    "elapsed_seconds": 612.5,
    "stdout_stderr_tail": "..."
  },

  "unpatched": {
    "applied": true,
    "exit_code": 0,
    "drv_path": "/nix/store/....drv",
    "out_path": "/nix/store/....-repro-unpatched",
    "elapsed_seconds": 18.2,
    "stdout_stderr": "...",
    "stdout_stderr_log_sha256": null
  },

  "patched": {
    "applied": true,
    "exit_code": 0,
    "drv_path": "/nix/store/....drv",
    "out_path": "/nix/store/....-repro-patched",
    "elapsed_seconds": 17.9,
    "stdout_stderr": "...",
    "stdout_stderr_log_sha256": null
  },

  "passthru_tests_ground_truth": [
    { "name": "passthru.tests.basic",        "drv_path": "/nix/store/....drv", "kind": "passthru.tests" },
    { "name": "nixosTests.systemd-coredump", "drv_path": "/nix/store/....drv", "kind": "nixosTests"     }
  ],

  "sbom_delta_attempted": false,

  "dispatch_outcome": "ok"
}
```

Locked invariants:

- **`schema_version`** is the literal `"1.0.0"` for v1.
- **Truncation rule.** `stdout_stderr` carries the **last 64 KiB** of combined stdout+stderr. If the actual log exceeds that cap, the full log is persisted as `build.log` adjacent to `build.json` and `stdout_stderr_log_sha256` references it. Reproducer scorers operate on the inline `stdout_stderr` field; oversize logs are scored on the truncated tail (acceptable because all reproducer signals must be ≤ 200 chars per the contract floor).
- **`applied` semantics.** Each operation reports `applied` independently. A failure in one operation does NOT mark subsequent operations as `applied: false`. They are simply recorded with whatever they did or did not produce, plus the failure reference.
- **`dispatch_outcome` enum.** One of `ok`, `refused-no-patch`, `refused-no-reproducer`, `patch-apply-failed`, `infra-failure`. The Steward gate consumes this for auto-merge eligibility.
- **No model fields.** Builder is deterministic; `build.json` does NOT carry a `model` block or `prompt` block. The replay invocation entry for the builder role likewise omits these fields (its `model.family` is `deterministic-no-model`, mirroring the resolver invocation).

---

## 4. Replay invocation shape

Builder appends a single replay invocation to `replay.json.roles[]` per run:

```json
{
  "invocation_id": "...",
  "role": "builder",
  "started_at": "...",
  "ended_at": "...",
  "model": {
    "family": "deterministic-no-model",
    "vendor": "internal",
    "model_id": "trace-builder-v0.1.0",
    "version": "0.1.0",
    "sampling": { "temperature": 0, "top_p": 1, "max_tokens": 1 }
  },
  "prompt": null,
  "inputs": [
    { "path": "patch.diff",      "sha256": "..." },
    { "path": "reproducer.nix",  "sha256": "..." },
    { "path": "package.nix",     "sha256": "..." }
  ],
  "outputs": [
    { "path": "build.json", "sha256": "..." }
  ],
  "patcher_invocation_id":     "...",
  "reproducer_invocation_id":  "...",
  "rng_seed": null,
  "validators_passed": ["build-json-shape-valid"],
  "network_policy_applied": "substituter-only",
  "host_system": "x86_64-linux",
  "nix_version": "2.33.3"
}
```

`network_policy_applied: "substituter-only"` reflects SPEC §0.3 ("Network is allowed only in Scout (feeds) and Builder (substituter)"). Builder may consult `cache.nixos.org` and configured substituters; it does NOT consult arbitrary URLs and does NOT publish results during the build.

---

## 5. BuildRunner Protocol

The dispatcher abstracts the build invocation behind a Protocol so tests can inject a `FakeBuildRunner` and the real implementation lands once Linux infra is reachable.

```python
class BuildRunner(Protocol):
    """Encapsulates a single nix-build invocation."""

    def run(
        self,
        *,
        nix_expression: str,         # the `-E '<expr>'` argument or a file path with `-A <attr>`
        cwd: Path,                    # working directory (a nixpkgs checkout)
        timeout_seconds: int,
    ) -> BuildOutcome:
        ...


@dataclass(frozen=True)
class BuildOutcome:
    exit_code: int
    drv_path: str | None
    out_path: str | None
    stdout_stderr: str
    elapsed_seconds: float
```

Implementations locked for v0:

- **`FakeBuildRunner`** — returns a caller-supplied `BuildOutcome`. Used in the unit suite. No Nix dependency.
- **`LocalNixBuildRunner`** — shells out to `nix-build` on `$PATH`. Produces a `BuildOutcome` from the subprocess return; truncates `stdout_stderr` per §3's 64 KiB rule. Deferred until a Linux host is reachable.

Future implementations: `RemoteSSHBuildRunner` (perdurabo-shaped), `GitHubActionsBuildRunner` (CI-shaped). Out of scope for v1.

---

## 6. Refusal & failure conditions

Builder is deterministic; "refusal" means the bundle did not satisfy a structural precondition:

| Condition | `dispatch_outcome` | Notes |
|---|---|---|
| `patch.diff` missing or is a refusal block | `refused-no-patch` | Builder writes `build.json` with `patch_apply.applied: false` and stops. Reproducer fields not populated. |
| `reproducer.nix` missing or is a refusal block | `refused-no-reproducer` | Builder runs §2.1–§2.2 (patch-apply + patched-build) but skips §2.3. Reproducer fields show `applied: false`. |
| `git apply --check` fails | `patch-apply-failed` | §2.2 and §2.3 are skipped. The `patched_build` and `unpatched`/`patched` fields show `applied: false` with `reason: "patch-apply-failed"`. |
| Subprocess error (nix-build hung, OOM, etc.) | `infra-failure` | Whatever phase failed records the exception detail. Subsequent phases skipped. |
| All operations completed (regardless of build success) | `ok` | The fact that a build *failed* is recorded as `outcome: failed`; that is NOT a dispatch refusal — it's data. |

Distinction worth keeping clear: **a failed build is a successful Builder run**. Builder's job is to record what happened; the verdict on whether the build outcome means the patch is acceptable belongs to scorers and Steward.

---

## 7. Steward consumption

The Steward gate reads `build.json` to make the `bundle.kind=auto-merge` decision. Locked rules for v1:

| Field | Required for `auto-merge` |
|---|---|
| `patch_apply.applied == true` | yes |
| `patched_build.outcome == "succeeded"` | yes |
| `unpatched.exit_code` recorded | yes (any value) |
| `patched.exit_code` recorded | yes (any value) |
| Reproducer scorer `repro-unpatched-fails == 1.0` (or proxy) | yes |
| Reproducer scorer `repro-patched-passes == 1.0` | yes |
| `dispatch_outcome == "ok"` | yes |

A bundle with `dispatch_outcome != "ok"` is automatically downgraded to `human-review-required` (or `advisory-only` for the patcher-refused case). The downgrade `kind_reason` mirrors the `dispatch_outcome` value.

---

## 8. Open questions parked

1. **Closure-scoped reverse-build verification.** Should Builder also rebuild a sample of the reverse closure (e.g., 5 random downstreams of the patched attr) to detect ABI/API breakages? v1 says no (out of scope, not blocking auto-merge); v2 may add this when blast-radius scoring matures.
2. **sbom-delta computation.** Reserved field; v1 leaves empty. Computing it requires evaluating the closure twice (pre-patch and post-patch) and diffing — significant extra build time per bundle.
3. **Multi-attr CVEs.** Like Reproducer v1, Builder v1 assumes one affected attr per bundle. Multi-attr bundles need either a build-per-attr loop or a bundle-redesign; v1 punts.
4. **Hydra integration.** SPEC §6.0 calls out v1 ("when Builder saturates Actions") as the time to migrate to a Hydra instance. v0 Builder uses the BuildRunner Protocol so the Hydra-shaped variant is a drop-in implementation.

---

## 9. What this document does not cover

- The exact Nix expression strings used per operation (those are implementation details inside `agents/builder/`).
- The 64 KiB truncation algorithm specifics (locked for v1: take the trailing 65536 bytes after UTF-8-decoding-best-effort with replacement; persist full log to `build.log` if truncated; record `stdout_stderr_log_sha256` on the truncated record only).
- Steward's `.rego` rules consuming `build.json`. Those land alongside the Steward arc; this document is the contract Steward keys off of.
