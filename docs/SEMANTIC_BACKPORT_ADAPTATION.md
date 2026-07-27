# Semantic backport adaptation — design note (pre-spend, unopened arc)

**Status:** design / scoping only. No code, no prompt version bumps, no live spend
yet. Opened 2026-07-27 as backlog finding #2 from the libarchive CVE-2026-15028
retirement (`docs/DECISIONS.md` 2026-07-27). This note exists so the arc is ready
to execute the moment Jason authorizes the live-eval spend it requires; it does
**not** open the arc.

## The gap this closes

The source-backport lane assumes the upstream fix patch applies **verbatim** to
the nixpkgs-pinned source. The Patcher transcribes `upstream-fix.patch`; the
Reviewer grades that transcription byte-for-byte. libarchive CVE-2026-15028 broke
that assumption: the upstream fix (`c161620`) rewrote `tar_atol_base_n()` to use
`archive_ckd_mul_i64`/`archive_ckd_add_i64`, helpers absent from the pinned
libarchive 3.8.7, so the verbatim patch cannot apply to the pinned base (caught
now, pre-spend, by `trace bundle preflight` — backlog #1, shipped `2229f7e`).

A correct fix for that class needs a **semantic adaptation**: restructure the
*pinned* source's actual code to carry the fix's behavior, using the pinned
base's own idioms (here: guard the digit read before advancing `p`, keeping
3.8.7's `l>limit` overflow check + `(sign<0)?-l:l` return, without the `ckd`
helpers). The pipeline cannot produce this today because the Patcher never sees
the affected `.c` source and the Reviewer grades transcription, not equivalence.
This arc gives the Patcher source awareness and the Reviewer a semantic-equivalence
verdict.

## Source-input provenance

The Patcher's `assemble_user_content` (`agents/patcher/runner.py`) today includes
finding / upstream-ref / impact / maintainers / `package.nix` / `upstream-fix.patch`
— but **not** the affected source. The arc must add the pinned source of exactly
the files the upstream fix touches, from a provenance-clean origin:

- **Origin:** the same `pkg.src` the preflight already unpacks (nix fixed-output
  fetch at the pinned `nixpkgs_rev`) — reuse `preflight.unpack_pinned_source` so
  there is one source-of-truth for "the pinned base."
- **Scope:** only the files named in `upstream-fix.patch` hunks (not the whole
  tree) — bounded context, and it keeps the model from wandering.
- **Hashing:** the included source files get per-file sha256 in the invocation
  sidecar (same discipline as every other replay input) so a replay re-run
  verifies the Patcher saw exactly the bytes we claim. This is a **new
  replay-critical input** → `replay.json` schema addition, gated behind a
  `schema_version` bump so old bundles still validate.
- **Offline boundary:** the source is fetched at **bootstrap** time (dev host,
  network OK) and baked into the bundle as a replay input; the Patcher itself
  stays offline at replay time (no network contract change — the offline-by-
  default execution contract is preserved).

## Patcher contract change (`patcher.v4`)

- New capability: given the pinned source + `upstream-fix.patch` as a *reference
  intent* (not a transcription target), author a patch that applies to the pinned
  base and reproduces the fix's behavior.
- Refusal rules must gain a clause: refuse when the base has diverged so far that
  a faithful adaptation cannot be grounded in the provided source (don't
  hallucinate helpers). This keeps the "honest refusal" property.
- The verbatim-transcription path stays the default; adaptation is entered only
  when the preflight of `upstream-fix.patch` against the pinned source **fails**
  (i.e. adaptation is the fallback for exactly the class preflight flags). Wiring:
  bootstrap runs preflight; on failure it does not auto-retire but routes to the
  adaptation lane.

## Reviewer contract change (`reviewer.v6`)

- New verdict dimension: **semantic equivalence** — does the Patcher's adapted
  patch produce the same security-relevant behavior as `upstream-fix.patch`,
  given the base divergence? This replaces the byte-transcription check *for the
  adaptation lane only* (the verbatim lane keeps `patch_comparison`).
- Cross-family rule unchanged (Opus Patcher / Sonnet Reviewer).
- Output schema: a new optional `equivalence_assessment` block (mirror the
  `patch_comparison` additive-optional pattern just shipped in `7b23568` — add to
  `policy/reviewer-output-schema.json` with `additionalProperties:false` intact,
  behind a schema-version bump if it becomes required for the adaptation lane).

## Preflight boundary (what stays / what changes)

- `trace bundle preflight` remains the **verbatim-applicability** gate and the
  **entry condition** for the adaptation lane (fail → adapt, not → retire).
- Preflight is **not** extended to judge adapted patches — that is the Reviewer's
  job (semantic equivalence is a model judgment, not a `patch -p1` outcome). The
  adapted patch still goes through the real Builder cert (compile + reproducer) as
  the ground-truth applies+builds gate.
- One reusable seam to extract: `preflight.unpack_pinned_source` becomes the
  shared "unpack the pinned base" primitive for both preflight and the Patcher's
  source-input assembly.

## Evaluation set

- **Positive canaries:** the retired/known base-mismatch cases where a semantic
  adaptation is known-correct — libarchive CVE-2026-15028 (hand-verified target
  shape exists), plus any future preflight-flagged candidates. **Do not** train or
  eval on a hand-authored adaptation that is then fed back for transcription
  (circular — called out in DECISIONS).
- **Negative controls:** verbatim-lane bundles (zlib, sqlite, requests backports)
  must still pass unchanged — the adaptation lane must not regress the verbatim
  lane. Run the existing source-backport cohort as a regression gate.
- **Metric:** adapted patch (a) applies to pinned source, (b) Builder cert green
  (compile + reproducer/reviewer-attested), (c) Reviewer semantic-equivalence
  verdict=accept, cross-family. Track `patch_rate` (adaptation lane) separately
  from the verbatim lane; a contract-correct refusal on an un-adaptable base is a
  valid outcome, not a productivity number.

## Rollback criteria

- `patcher.v4` / `reviewer.v6` are new prompt versions — the prior versions stay
  in place and the lane is opt-in per bundle (entered only via preflight failure).
  Rollback = stop routing preflight failures to the adaptation lane; the verbatim
  lane and every existing bundle are untouched.
- The schema additions are additive-optional (the `patch_comparison` pattern), so
  a rollback of the prompt work leaves the schema forward-compatible, not broken.
- Hard stop: if the adaptation lane produces a patch that passes Reviewer but
  fails Builder cert (semantic verdict disagreeing with ground-truth build) on ≥1
  canary, the Reviewer's equivalence grading is not trustworthy → halt the lane,
  do not auto-merge any adaptation, treat all as human-review-required until the
  disagreement is understood.

## Estimated spend

- **Design/wiring (no model spend):** source-input assembly + schema bumps +
  preflight seam extraction + local FakeAdapter end-to-end. Free.
- **Prompt iteration (live):** `patcher.v4` + `reviewer.v6` iteration on the
  libarchive canary — order ~$0.4–0.5/Patcher run × several iterations
  (cf. the $0.38 libarchive Patcher run), + ~$0.08/Reviewer run. Budget a handful
  of iterations: ~$3–5 for prompt convergence on one canary.
- **Cohort regression (live):** re-run the source-backport verbatim cohort to
  confirm no regression — bounded by the existing cohort size × per-role cost.
- **CI:** each canary cert is one `bundle-linux-cert.yml` dispatch (Builder build
  time; no extra model spend beyond the replay above).
- **Total to a first green adaptation canary:** low tens of dollars of live spend,
  dominated by prompt iteration. This is the gate that needs Jason's authorization.

## Slice plan + status

- **Slice 1 — SHIPPED (`8a8e0a1`, 2026-07-27).** Pure refactor: extracted the
  pinned-source unpack into `tools/trace_cli/pinned_source.py`, shared by the
  preflight and (slice 2) the Patcher source-input assembly. No behavior/schema/
  prompt change. Counter 0/5→1/5, baseline `2229f7e`.
- **Slice 2 — SHIPPED (2026-07-27).** Atomic: `source-context/` signed input +
  `preflight.json` verdict + bundle/replay `schema_version` 1.1.0 (`oneOf`-gated,
  grandfathers all 117 existing source-backports at 1.0.0) + `patcher.v4`
  (verbatim-on-true / grounded-adaptation-on-false / refuse-if-ungroundable) land
  together. Six `codex review --uncommitted` rounds + the `security-review` skill;
  eight findings fixed in-slice (schema loophole, hunk-aware diff parsing, verify
  dedup, empty-lane consistency, root/leaf/stale symlink + source-context hygiene),
  final verdict clean. Suite 1900 passed. No live spend (FakeAdapter). See
  DECISIONS 2026-07-27 "slice 2".
- **Slice 3+ — live prompt iteration** on the libarchive canary + verbatim-cohort
  regression (the authorized-spend phase), then cert.

### Slice 2 implementation spec (codex-confirmed)

1. **Storage.** At bootstrap (`bundle assemble`), write the pre-patch copies of
   exactly the files named in `upstream-fix.patch` hunks into `source-context/`,
   preserving **normalized upstream-relative** paths, sourced from the pinned
   `pkg.src` via `pinned_source`. Reject absolute paths, `..`, symlinks, duplicate
   normalized paths, and any path outside the parsed diff's file set
   (path-traversal hardening — trace threat model item #4).
2. **Replay integrity.** Add an explicit **sorted** manifest of `{path, sha256}`
   entries (not an implicit glob), every entry `replay_critical: true`, folded
   into the signed bundle hash. Hashed at finalize.
3. **`patcher.v4`.** Do NOT ask the model to infer applicability. Feed the
   deterministic preflight result — `applies_verbatim: true|false` + bounded
   diagnostics — into the assembly. v4 transcribes verbatim on `true` (v3
   behavior) and authors a semantic adaptation grounded in `source-context/` on
   `false`; refuses if no adaptation can be grounded in the provided source.
   Source-context is always present for source-backports.
4. **Schema compatibility.** Bump `schema_version` on bundle + replay schemas via
   versioned `oneOf` branches, not a `const` swap or a bare enum: existing
   `1.0.0` bundles stay valid; a `1.1.0` **source-backport MUST** include the
   source-context manifest, a `1.1.0` non-source-backport MUST NOT (so "optional"
   never silently weakens the new contract). `bundle_schema_version` sha still
   covers drift.

Touch list: `tools/trace_cli/bundle.py` (assemble writes source-context +
finalize hashes the manifest), `tools/trace_cli/execute.py` +
`agents/patcher/runner.py` (load + assemble source-context + `applies_verbatim`),
`agents/patcher/prompt` (`patcher.v4`), `policy/bundle-schema.json` +
`policy/replay-schema.json` (oneOf version branches + manifest shape), a
diff-hunk-path parser (reuse/extend existing patch parsing), and FakeAdapter
end-to-end coverage. All no-spend up to and including FakeAdapter-green.

## Not started (live phase)

The live prompt-iteration + cohort-regression phase (slice 3+) is scope-approved
by Jason but spends model budget; the no-spend slice-2 wiring lands first.
This note's prose above the slice plan is scope only. Opening the arc requires Jason's live-spend
authorization (per the CLAUDE.md live-run cost discipline + the standing
large-workflow hold). Until then: verbatim lane + preflight gate is the shipped
behavior; base-mismatch candidates are retired (documented non-viable examples),
not adapted.
