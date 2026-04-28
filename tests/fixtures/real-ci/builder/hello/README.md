# `tests/fixtures/real-ci/builder/hello/`

Minimal staged bundle for the `builder.yml` Linux-runner smoke. Exercises
`LocalNixBuildRunner` end-to-end (Nix install → `nix-build` subprocess
plumbing → `build.json` shape → `replay.json` append) WITHOUT requiring
a real CVE, real nixpkgs checkout, or real upstream patch.

## Layout

| file              | purpose |
|-------------------|---------|
| `bundle.json`     | minimal bundle manifest. `kind=auto-merge` — but Builder doesn't validate the manifest against the bundle schema; this fixture is for Builder smoke only and is NOT meant to pass full Steward gating. |
| `finding.json`    | placeholder `cve_id=CVE-9999-99999` finding targeting `pkgs.hello`. The smallest reliably-buildable nixpkgs derivation. |
| `replay.json`     | resolver invocation only. Builder appends its own invocation. |
| `patch.diff`      | no-op patch (replaces `version = "2.12.1";` with itself). Never applied — the workflow runs Builder with `nixpkgs_checkout=None` so patch-apply is skipped. The file's presence is what gates Builder's `dispatch_outcome` away from `refused-no-patch`. |
| `reproducer.nix`  | minimal `{ pkgs ? import <nixpkgs> {} }: { unpatched, patched, test }` — both `unpatched` and `patched` resolve to `pkgs.hello`; `test` is a `runCommand` that emits synthetic signal lines. |
| `default.nix`     | re-exports `pkgs.hello` so Builder's patched-build phase (`nix-build -A hello`) finds the attr in the bundle directory. |

## What the smoke proves

- DeterminateSystems Nix install + magic-nix-cache work in the runner.
- `LocalNixBuildRunner.run` shells out to `nix-build` correctly.
- The four Builder operations (`patch-apply` skipped, `patched-build`,
  `unpatched`, `patched`) produce a `build.json` validating against
  `policy/build-output-schema.json`.
- The replay invocation block is appended to `replay.json` with the
  `model.family='deterministic-no-model'` shape.
- `nix-build` actually exits zero on this runner environment.

## What the smoke does NOT prove

- That a real CVE patch applies cleanly in CI (patch-apply is skipped).
- That a real reproducer signal discriminates pre-fix from post-fix
  (unpatched/patched both build the same `pkgs.hello`; the signal lines
  are synthetic).
- That Steward's auto-merge gate accepts the resulting bundle (rules
  4 + 5 require signed_manifest + provenance.jsonl; this fixture has
  neither).
- That the cohort-1 inner-loop bundles build under real nixpkgs.

A second fixture / workflow extension lands when Builder is wired
against a real nixpkgs checkout; this one is the v0 smoke for "the
runner can call nix-build at all."
