# Concepts

A single-read orientation. Each section is one paragraph; the deep-dives live in the per-role contract docs and `DECISIONS.md`.

---

## What trace is

trace is an **agent-owned nixpkgs fork** that produces **merge-ready CVE evidence bundles**. The unit of output is a frozen directory of files (a "bundle") that says: here is a CVE, here is the affected derivation, here is the patch we propose, here is the proof the patch fixes the vuln, here is the human/automation verdict, here is the cryptographic signature attesting all of the above. trace does not push to upstream nixpkgs; it produces evidence that humans (or other automation) can audit and merge. The fork is the staging ground; the bundles are the artifact.

---

## Why a fork and not a PR bot

A nixpkgs PR bot would conflate two failure modes: "this CVE is fixable" and "this PR is mergeable today." Maintainer review, CI flakiness, channel-cut timing, and reviewer bandwidth all gate the second; trace cares about the first. A fork lets trace produce evidence at its own cadence, sign each bundle for downstream verifiers, and let humans pick which bundles to upstream and when. The fork is the substrate; bundles are the contract surface.

---

## The bundle

A bundle is a directory under `traces/example/CVE-XXXX-XXXXX--<attr>/` containing JSON, Markdown, Nix, and (for some CVEs) a binary PoC. The shape is locked in `policy/bundle-schema.json` and `docs/BUILDER_V1.md` §3. A bundle is **frozen** the moment Steward signs it, every replay-critical file is sha256'd into `signed_manifest.signed_files`, and the cosign signature anchors that hash set in the public Rekor transparency log. Mutating any file post-sign breaks verification; auditors can pin to a Rekor log index forever.

---

## The five-role chain

Each bundle is produced by five roles operating in sequence, each with its own contract doc:

1. **Scout** (`agents/scout/`), turns a CVE feed entry (NVD / GHSA) into a `finding.json` that names the affected nixpkgs attr, version, drv path, confidence.
2. **Cartographer** (cross-references nixpkgs structure), produces `impact.json` (rebuild blast radius) + `maintainers.json`.
3. **Upstream-ref-resolver** (`agents/upstream_ref_resolver/`), locates the upstream fix commit(s), classifies fix tier (security-patch-release / point-release-small-delta / major-version-jump), records prefetch hashes in `upstream-ref.json`. Also emits the `eligibility.verdict` that gates auto-merge.
4. **Patcher** (`agents/patcher/`), produces `patch.diff` + `patch-rationale.md`. Patcher is a model-backed role.
5. **Reviewer** (`agents/reviewer/`), produces `review.md` with verdict `accept` / `reject` / `defer`. Cross-family with Patcher (different model family) per the cross-family rule.

In parallel with Patcher/Reviewer, **Reproducer** (`agents/reproducer/`) produces `reproducer.nix` + `reproducer-log.txt` + `passthru-tests.json`: a sandboxed test that discriminates pre-fix from post-fix behaviour via a paired textual signal (SIGNAL_UNPATCHED / SIGNAL_PATCHED). See `docs/REPRODUCER_V1.md` §3.

**Builder** (`agents/builder/`) is the deterministic runner that consumes the human-authored / model-authored evidence: applies `patch.diff` to nixpkgs, builds the patched derivation, runs the reproducer's `unpatched.test` and `patched.test` attrs, asserts the signal substrings appear, writes `build.json`. Builder has no model.

**Steward** (`policy/steward.rego` + the gate workflow `.github/workflows/steward.yml`) is the merge-gate policy. Eleven rules (see `docs/STEWARD_V1.md`) operate on the bundle's static contents + Builder's runtime output to produce `allow: true | false`. Allow ⇒ cosign keyless OIDC signature is anchored in Rekor; deny ⇒ signing skipped, decision recorded.

---

## Bundle kinds

Every bundle declares one of three `kind`s in `bundle.json`. The kind picks which Steward rules apply.

* **`auto-merge`**, Steward enforces all 11 rules. Successful auto-merge produces a signed bundle that downstream automation can merge to upstream nixpkgs without further human review. The strictest path; demands a sandbox-positive Reproducer, a cross-family Patcher/Reviewer pair, an `eligible` upstream verdict, and high-confidence affected-derivation mapping.
* **`human-review-required`**, Steward enforces rules 4 + 5 only (signed-manifest consistency + provenance/replay agreement). Path for major-version-jumps, low-confidence mappings, or any case where automation should *signal* the issue but human judgment decides the merge. Signed when allowed.
* **`advisory-only`**, strictest content requirements but never merged automatically; trace publishes the evidence as a public advisory snapshot. Signed when allowed.

Today's corpus has all three: synthetic `hello` (auto-merge), real-CVE `bind` (auto-merge that correctly denies on rule-7 because no reproducer can be produced for a DNS-daemon CVE in sandbox), real-CVE `uriparser` (human-review-required, major-version-jump), real-CVE `libtiff` (auto-merge, deterministic-no-model corpus extension).

---

## The cross-family rule

For any model-backed role pair (Patcher/Reviewer and Patcher/Reproducer), the two models must come from **different families** (`anthropic-opus`, `anthropic-sonnet`, `openai-gpt-4`, etc.). Same-family pairs let an idiosyncratic family-wide bias hide behind itself: a bug in one model's parsing of a vuln description is more likely to also live in a sibling model than in a different family. The rule is enforced mechanically by the executor pre-call, not by trusting the models' own attestations. `replay.json:cross_family_rule_honored` carries the result; auto-merge is forbidden when it's `false`. See `docs/MODEL_EVAL_PLAN.md` for the qualification methodology that picks the v0-locked pair: `claude-opus-4-7` (Patcher) ↔ `claude-sonnet-4-6` (Reviewer) ↔ `claude-sonnet-4-5-20250929` (Reproducer, refusal/proxy-qualified only).

Vacuous case: `deterministic-no-model` is a separate family. A bundle whose Patcher is deterministic (e.g. a hand-authored backport whose patch.diff has no model attribution) trivially satisfies the cross-family rule against any model-backed Reviewer.

---

## Strict-output contract

Patcher, Reviewer, and Reproducer all emit text that the runner parses before writing files. Each role's prompt forces a `=== BEGIN <file> === ... === END <file> ===` block structure with no surrounding prose; any deviation is a parse refusal with a stable error class. This is "trust the markers, not the model": the model's claim only enters the bundle if its output parses cleanly. See `prompts/patcher.v1.md`, `prompts/reviewer.v1.md`, `prompts/reproducer.v1.md`. Refusals (the model declining to produce a file) are first-class outputs with their own shape (`refusal.json` / `reproducer-refusal.json`); they're evidence too, not failures.

---

## Replay and provenance

Every bundle ships a `replay.json` (canonical minimal restatement: which roles ran, which models, which prompt + input + output sha256s, sampling parameters) and a `provenance.jsonl` (append-only per-action log: every model call, tool invocation, validator check, file write). Steward rule-5 enforces that every `model_invocation` in `provenance.jsonl` has an exactly-matching `replay.json` invocation on (`invocation_id`, `model_id`, `prompt.sha256`, `inputs[].sha256` set, `outputs[].sha256` set). The two files are a closed system: replay says what was supposed to happen; provenance says what happened; they must agree. Disagreement is a hard reject.

---

## Signing identity

Every signed bundle is anchored to a single, locked workflow identity:

* **subject_regex**: `^https://github\.com/Ad-Astra-Computing/trace/\.github/workflows/steward\.yml@refs/(heads/main|tags/v[0-9][^/]*)$`
* **oidc_issuer**: `https://token.actions.githubusercontent.com`

Both fields live in `policy/signing-identity.json` and are pinned via cosign `--certificate-identity-regexp` + `--certificate-oidc-issuer` at verify time. The signing path is Sigstore keyless OIDC, no private key, which means the GitHub Actions workflow's OIDC claim *is* the identity. See `docs/SIGNING_V1.md`. Per-entry uniqueness is the Rekor log index; bundle.json carries `signed_manifest.rekor_log_index` + `rekor_uuid` (the latter resolved via Rekor public-API lookup, not the constant Rekor shard logID, see DECISIONS.md 2026-04-28 entry).

---

## What's deliberately out of v0 scope

See `docs/DECISIONS.md` *Deliberate non-goals for v0* for the full list. Highlights: no direct upstreaming to nixpkgs; no master / stable channels (only the fork); no derivations without `passthru.tests`; no cherry-picks or agent-original patches; no major-version-jumps without explicit human sign-off; no UI (bundles live as files; review happens in GitHub PRs against the fork); no novel-vulnerability discovery; no Hydra integration (deferred to v1 when Builder saturates GitHub Actions).

---

## Where to read next

* **Architecture & directory map**, `docs/ARCHITECTURE.md` (this doc's sibling).
* **The v0 design itself**, `SPEC.md` (rev 3, 22 April 2026).
* **Per-role contracts**, `docs/BUILDER_V1.md`, `REPRODUCER_V1.md`, `STEWARD_V1.md`, `SIGNING_V1.md`.
* **What's been decided & why**, `docs/DECISIONS.md` (append-only).
* **Model qualification methodology**, `docs/MODEL_EVAL_PLAN.md`.
* **Threat models**, `docs/SECURITY_CI_SUPPLY_CHAIN.md`, `SECURITY_PROMPT_INJECTION.md`.
* **Schemas**, `policy/*.json` (single source of truth for every file shape).
* **Steward gate policy**, `policy/steward.rego` (single source of truth for merge gating).
