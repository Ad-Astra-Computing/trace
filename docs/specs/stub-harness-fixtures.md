# Spec: stub-harness fixtures for handler-shaped flaws

- Status: Proposed
- Author: Ad Astra Computing Inc
- Date: 7 September 2026
- Related ADRs: none

## Problem

Three of the six live-lane bundles carry no behavioural proof. snipe-it, netron
and ntopng all ended reviewer-attested because the Reproducer refused under its
rule 3: the flaw sits in a request handler or a renderer that only runs inside a
live web application or a desktop GUI, and the Nix sandbox can host neither.
Each refusal was correct under the v15 prompt. The pattern will repeat, because
the by-name survey's small survivors are mostly web applications.

The refusals are also more conservative than the evidence already accepted
elsewhere. The mailpit fixture drops a Go test into the real source tree and
calls the real function; nothing stands up a mail server. The ntopng handlers
need one more step, stand-ins for the objects the daemon would have supplied,
and then they run the same way. A hand-built prototype on 7 September 2026 ran
the two ntopng delete handlers under a Lua stub that answers every capability
check with false. The unpatched tree called the destructive function; the
patched tree answered `not_granted` first. That is a two-arm discrimination on
the real handler files.

What is missing is permission to stub the ambient environment, a rule that
keeps the stub from becoming a tautology, and a record on the wire of what was
stubbed so a reader can weigh the proof.

## Goals

- The Reproducer may write a fixture that loads the patched code unit under
  its own interpreter with the environment the host would have supplied
  replaced by stubs, when a live service or GUI is the only alternative.
- The fixture declares in `reproducer-log.txt` what it stubbed, and the
  declaration is parsed and checked, not trusted.
- A stub that replaces anything the patch touches is refused before any cert
  spend.
- Reports and the seed index show these fixtures apart from fixtures that run
  the real program end to end.

## Non-goals

- A new evidence path. The Builder builds two arms and the signal scorers
  judge them exactly as for any other fixture, so `auto_merge_evidence_path`
  stays `reproducer` and the Steward rules 7, 9 and 10 are unchanged.
- Standing up services, listeners, browsers or displays. The sandbox contract
  does not move.
- Memory-safety classes. A stub cannot make a silent out-of-bounds read
  observable; those still need the ASAN path or a refusal.
- Rewriting the proxy mechanism. A stub-harness fixture proves both arms and is
  not a proxy; the two declarations are mutually exclusive.

## Design

### The harness section

When a fixture stubs any part of the environment the code under test requires,
`reproducer-log.txt` carries a fourth section after `=== patched ===`:

```
=== harness ===
harness_class: stub-ambient
target_files: scripts/lua/rest/v2/delete/endpoints.lua, scripts/lua/rest/v2/delete/recipients.lua
stubbed: ntop, rest_utils, endpoints, recipients, auth
effect: the handler calls endpoints.reset_configs and recipients.cleanup for a user without the notifications capability
```

`harness_class` is an enum with one value for now. `target_files` names the
files the harness loads unaltered from each arm's source tree, repository
relative. `stubbed` names the modules and globals the harness replaced.
`effect` is one line naming the observable the unpatched arm exhibits; it is
what `SIGNAL_UNPATCHED` reports and what the patched arm must prevent.

The parser in `agents/reproducer/parser.py` accepts the section, requires all
four keys, rejects a `harness_class` outside the enum, and rejects a log that
carries both `=== harness ===` and `=== proxy ===`. The parse result exposes
the declaration the way it exposes proxy metadata.

### The tautology guard

The harness proves something only if the code it runs is the code the patch
changed and the stubs stand in for things the patch did not change. `bundle
finalize` enforces both halves whenever `reproducer-log.txt` has a harness
section:

- every `target_files` entry must be a file that `patch.diff` or
  `upstream-fix.patch` touches (a nested source patch inside `patch.diff`
  counts, so the check reads both the outer `+++ b/` headers and the inner
  ones), and
- no `stubbed` entry may match the basename, with or without extension, of a
  file either patch touches, unless that file is itself a `target_files`
  entry. A module that shares its name with the handler that requires it
  (ntopng's `endpoints` module and its `delete/endpoints.lua` handler) is
  the ambient environment, not the code under test, and the two-arm
  discrimination proves the target file was loaded rather than shadowed:
  a harness that replaced the target with a same-named stub would run the
  same code in both arms and fail to discriminate.

A violation refuses the finalize with the offending name in the message.
Nothing downstream of finalize (probe, cert, sign) runs on an unfinalized
bundle, so the guard sits ahead of all spend.

### The prompt

`prompts/reproducer.v16.md` amends rule 3 and `prompts/reproducer.v17.md` clarifies its refusal clause (the sink receiving the unescaped payload is the effect for an injection class; a DOM stub is a few recording objects, not a DOM). Before refusing because the flaw
needs a running service, session or display, the Reproducer asks whether the
patched unit can be loaded headlessly with the ambient environment stubbed. If
it can, it writes a stub-harness fixture under these rules:

- The Builder evaluates the fixture against the patched nixpkgs tree, so the
  patched arm applies the package's own patch list to the pinned source and
  the unpatched arm applies the same list with the CVE patch filtered out.
  Both arms run one identical harness over the target files, unaltered.
- Stubs may replace only what the host would have supplied: globals the
  framework injects, request, session and authentication objects, sibling
  modules the patch does not modify, database and network clients. A stub
  never reimplements a file the patch touches and never replaces the function
  that contains the guard.
- The stub environment must let the unpatched arm exhibit the vulnerable
  effect, so `SIGNAL_UNPATCHED` reports the effect, not the absence of a
  guard. A harness that only proves "the new check is present" is a diff
  match, not a proof.
- The log carries the harness section above.

The runner's default prompt path moves to v16 and the locked test moves with
it.

### Reporting

`trace report` counts fixtures with a harness section separately from fixtures
without one. Seed index rows describe them as two-arm with a stub harness.

## Security

Model output still executes only inside the Nix sandbox, offline, as before;
the harness changes what the fixture contains, not where it runs. The new code
paths are text parsing of a bundle-local log and header extraction from two
patch files, both fail-closed. The residual risk is epistemic rather than
executional: a stub can encode a wrong belief about the framework's contract,
and then the harness proves less than it appears to. That is why the
declaration is mandatory and visible, why the guard refuses stubs that overlap
the patch, and why these fixtures are labelled apart in every report.

## Tests

- Parser: a well-formed harness section parses; a missing key, an unknown
  class and a log carrying both harness and proxy sections are rejected; a log
  without the section still parses as before.
- Finalize: a stubbed name that is a patched file's basename refuses, unless
  that file is a declared target; a target
  that neither patch touches refuses; a nested source patch's files count as
  touched; a clean declaration passes; a log without the section is unaffected.
- Prompt: the default path is v16.
- Report: the harness count appears and sums correctly with the other counts.

## Rollout

ntopng CVE-2026-86090 is the pioneer. Its Reproducer is re-run under v16, the
payload preflight and the two-arm probe run locally, the bundle is finalized
with `--evidence-path reproducer` and the cert is dispatched with the probe
gate on. netron (a DOM shim around `view.js`) and snipe-it (a Laravel policy
check under a stub user) follow if the pioneer's cert passes.
