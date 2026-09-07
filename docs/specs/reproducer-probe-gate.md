# Spec: a two-arm probe as a hard gate before cert

- Status: Draft
- Author: Ad Astra Computing Inc
- Date: 7 September 2026
- Related ADRs: none

## Problem

The Reproducer's own log is a claim, not evidence. On chirp CVE-2026-78136 the
model's fixture was wrong four ways and its log reported success for all of them.
The defects surfaced only because the fixture was built and run by hand before
cert. Nothing in the pipeline forces that step, so an unattended run would have
dispatched a cert on a fixture that had never executed, and either burned the run
or, worse, passed on a fixture that discriminates for the wrong reason.

The machinery already exists. `agents/reproducer/sampling.build_probe_fn` runs
the real two-arm Builder over an isolated copy of a bundle, restores the nixpkgs
checkout afterwards, and judges the result with the same signal scorers the cert
uses. It is only reachable through pass@K sampling, which spends model calls to
draw candidates. There is no way to run it once over the reproducer a bundle
already has.

## Goals

- One command runs the bundle's committed reproducer through the real two-arm
  Builder locally and records the verdict beside the bundle.
- The verdict is bound to the exact reproducer bytes it judged, so an edited
  fixture invalidates it.
- Cert dispatch can require a green, current probe and refuse otherwise.
- A fixture that failed on infrastructure rather than on its own logic is
  reported as a probe error, never as a non-discriminating verdict.

## Non-goals

- Sampling new fixtures. That stays in `trace reproducer sample`.
- Replacing the cert. The probe runs on whatever machine the operator has; the
  cert runs on the pinned Linux runner and remains the evidence of record.
- Writing `build.json`. The cert's `build.json` is the one that gets installed;
  the probe writes its own sidecar.

## Design

`trace bundle probe <bundle> --nixpkgs-checkout DIR` wraps `build_probe_fn` over
the bundle's own `reproducer.nix`, `reproducer-log.txt` and `passthru-tests.json`.
It refuses when any of the three is missing, when the checkout is not a clean git
tree at the bundle's pinned revision (the same checks pass@K applies, factored out
so both use one implementation), or when the bundle has a Patcher refusal or is
advisory-only.

It writes `probe.json`:

```
{
  "schema_version": "1.0.0",
  "probed_at": "...",
  "reproducer_sha256": "...",
  "reproducer_log_sha256": "...",
  "nixpkgs_rev": "...",
  "discriminates": true,
  "signal_unpatched_present": true,
  "signal_patched_present": true,
  "signal_specificity_ok": true,
  "detail": "unpatched=...; patched=...",
  "build_json_sha256": "..."
}
```

and keeps the probe workspace's `build.json` as `probe-build.json` so the arms'
output is inspectable. Exit codes: 0 discriminates, 3 does not, 4 probe error
(infrastructure), 2 refused precondition.

`trace bundle probe --check <bundle>` is the gate form. It exits 0 only when
`probe.json` exists, `discriminates` is true, and both recorded hashes match the
current files. It runs no build. The orchestrator calls it before dispatching a
cert, and an operator can call it by hand.

Alternative rejected: making `replay --execute --role reproducer` run the probe
automatically. That couples model spend to a Linux build and would make the
Reproducer step fail on hosts that cannot build, which hides whether the model
call itself worked.

## Acceptance criteria

- [ ] A bundle whose fixture discriminates yields `probe.json` with
      `discriminates: true` and exit 0.
- [ ] A fixture whose unpatched arm never fires yields `discriminates: false` and
      exit 3, with the arm detail recorded.
- [ ] A build that fails on infrastructure yields exit 4 and no `probe.json`
      verdict.
- [ ] Editing `reproducer.nix` after a green probe makes `--check` fail.
- [ ] Editing `reproducer-log.txt` after a green probe makes `--check` fail.
- [ ] `--check` on a bundle with no `probe.json` fails.
- [ ] A dirty checkout, or one at the wrong revision, is refused before any build.
- [ ] The bundle's `build.json` is never written by the probe.
- [ ] The nixpkgs checkout is left at pristine HEAD after the probe.

## Risks and open questions

The probe runs on the operator's host, which may differ from the cert runner in
store contents and platform. A green probe raises confidence in the fixture, it
does not replace the cert. The specificity scorer is advisory and does not affect
the exit code, matching pass@K.
