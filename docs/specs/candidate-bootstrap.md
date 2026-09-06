# Bootstrapping a bundle from a screened candidate

## Why

The beat-upstream screen produces a shortlist: on 6 September 2026 it found 105
CVEs where an upstream fix exists and the nixpkgs tree does not carry it. Turning
one into a bundle is currently hand work. Doing it twice (wget CVE-2026-16599 and
chirp CVE-2026-78136) took the same six steps both times, and none of them
involved judgement:

1. copy `package.nix` for the attr out of the pinned nixpkgs revision
2. fetch the upstream fix commit as a patch file
3. write `impact.json` and `maintainers.json` placeholders
4. reshape the screen's `resolver-input.json` so the candidate ref is tagged
   `source-backport`
5. run `bundle assemble`
6. run `bundle preflight` against the extracted pinned source

At 105 candidates the hand path is the bottleneck, and each hand-written file is
somewhere a typo can put a wrong claim into a signed bundle.

## What this adds

`trace bundle bootstrap` takes one screen inbox entry and produces a staged
directory that `bundle assemble` accepts, or runs assemble itself.

```
trace bundle bootstrap \
    --inbox-entry <screen-inbox>/CVE-2026-16599 \
    --nixpkgs-checkout ~/code/nixpkgs \
    --nixpkgs-rev c2460146f8bed481f8f0848b193dc2bfd5cb6a54 \
    --out traces/example/CVE-2026-16599--wget-ftp-opie-backport
```

Inputs it reads from the entry: `finding.json`, `resolver-input.json`,
`scout-input.json`. Everything else is derived.

## Behaviour

**package.nix.** Resolved from the checkout at the pinned revision. A by-name attr
lives at `pkgs/by-name/<first two letters>/<name>/package.nix`. Anything else needs
`--package-path`, given relative to the repository root. The file is read with
`git show <rev>:<path>` so the pinned bytes are used rather than the working tree.

**upstream-fix.patch.** Fetched from the first fix commit in the candidate ref.
GitHub, GitLab and Codeberg all serve `<commit url>.patch`. The fetcher is
injectable so tests never touch the network. No fix commit means no bootstrap:
exit non-zero and say so.

**impact.json and maintainers.json.** Written as placeholders with
`analysis_status: "skipped-v0"` and an `analysis_reason` saying the counts carry
no evidentiary weight. This is honest rather than convenient: the routing policy
sends an unanalyzed impact to human review, which is the correct disposition for
an experimental source backport.

**resolver-input.json.** The screen's candidate ref is copied through with
`tier_hint` forced to `source-backport`, which is what authorizes the Patcher to
author a fix rather than bump a version. The version fields stay as the screen
recorded them.

**Refusals.** Bootstrap refuses, with a message naming the cause, when: the entry
has no `resolver-input.json`; no candidate ref carries a fix commit; the attr's
`package.nix` cannot be located; or the output directory already exists and
`--force` was not given.

## What it deliberately does not do

It does not run the Patcher, fetch the pinned source, or run preflight. Those stay
separate so the no-spend gates keep being run on purpose rather than as a side
effect. It does not invent severity, CVSS or blast-radius numbers.

## Version drift

Found while bootstrapping privatebin CVE-2026-55891: the screen reads its own
nixpkgs snapshot, while the pinned revision is passed in separately. The screen
had recorded 2.0.6 and the pinned revision carried 2.0.5, so the bundle would have
been built against the wrong base. Preflight catches that eventually, but only
after the source has been fetched and only if the patch happens not to apply.

Bootstrap now compares the version the candidate names against the one the pinned
package file declares and refuses when they differ, naming both. `--allow-version-drift`
proceeds anyway. A package that computes its version rather than declaring a
literal is not checked, since a check that cannot read the version must not refuse.

## Testing

Unit tests cover each refusal, the by-name path derivation, the `--package-path`
override, the placeholder shapes against their schemas, and the `tier_hint`
rewrite. The patch fetcher is injected. One test asserts the output of a bootstrap
is accepted by `assemble_bundle` unchanged, so the two stay in step.
