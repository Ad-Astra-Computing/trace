# Adaptation capability summary (v0.7.0)

*Compiled 27 July 2026. Every figure below is cited to a source in this
repository. Where a number is a moving target or was measured under
conditions that no longer hold, the caveat is stated inline rather than
dropped.*

trace is a research artifact, not a product. This note answers one
question honestly: **on the source-backport / semantic-adaptation lane,
what can the pipeline demonstrably do today, and where does it
visibly fall short?** It deliberately makes no frontier-parity or
state-of-the-art claim. The register matches the README: the v0 thesis
is a question ("can agent systems turn known upstream fixes into
maintainer-trustworthy nixpkgs bundles faster than human workflows?"),
not an assertion of success.

## The lane in one paragraph

A CVE flows through six roles (Scout, UpstreamRefResolver, Patcher,
Reviewer, Builder, Reproducer) plus a Steward adjudicator, each with an
explicit contract. The **verbatim** path transcribes an upstream fix
patch onto the pinned nixpkgs base and grades the transcription
byte-for-byte. The **adaptation** path is the harder case: when the
upstream fix cannot apply verbatim because the pinned base has diverged,
the Patcher must restructure the pinned source to carry the fix's
behavior using the base's own idioms, and the Reviewer must judge
semantic *equivalence* rather than transcription fidelity. This summary
is mostly about that second path, because it is where capability and
limitation are both sharpest.

## What is demonstrably working

**Cert-green evidence bundles.** The current machine-verified corpus
total, from a `corpus_readiness.py` re-run on 27 July 2026, is **84
cert-green positives + 55 negatives**
([`data/reports/corpus-readiness-20260727.json`](../data/reports/corpus-readiness-20260727.json)).
Both pilot thresholds (50 positives / 25 negatives) are cleared with gap
0, and no auto-merge positive is uncerted. The overall pilot-ready gate
now reads **READY** (`pilot_ready=true`, `blocking=[]`): there are **0
genuinely-broken bundles** and **0 non-git-provenance evidence bundles**.
The readiness enumerator excludes two classes that are not corpus
pollution: **6 self-declared schema-negative authoring fixtures**
(Authoring-LoRA Tier-B bundles whose own `expect.json` declares
`overall="invalid"` with `expected_failure.doc="upstream-ref.json"`, so
`tests/schema/test_fixtures.py` *requires* their `upstream-ref.json` to
fail validation — test-asserted-invalid by design, kept visible in the
report), and **21 authoring-only training pairs** previously
mis-enumerated as evidence bundles (they carry `authoring-example.json`
and no `bundle.json`). Both classes are excluded via fail-closed guards
so a genuinely-malformed evidence bundle is never hidden. The trend on
the certified reviewer
set: 41/50 then 45/50 (15 June, `docs/DECISIONS.md:4597`, `:4676`), 70/50
(18 June, `:6021`), 77/50 (21 June, `:6365`), 84/55 (27 July).

Strongest named examples, each with a green Linux cert run:

| Bundle | Note | Cert |
|---|---|---|
| `CVE-2025-26625--git-lfs` | first model-attested + sandbox-positive + Linux-cert-green auto-merge bundle | run 26075978701 (`docs/SEED_INDEX.md:23`) |
| `CVE-2025-2337--matio` | ASAN-instrumented N=3 anchor | run 26440903201, green 26 May (`docs/SEED_INDEX.md:33`) |
| `CVE-2025-8176--libtiff` | Phase 3 first cert-green | run 26647927663, green 29 May (`docs/SEED_INDEX.md:34`) |
| `CVE-2026-1998--micropython` | first cert-proven overlay-patch-shape bundle | run 26432528586, green 26 May (`docs/SEED_INDEX.md:35`) |

**Fork PRs as accuracy artifacts.** Eleven PRs (#13 to #23) were opened
against the `Ad-Astra-Computing/nixpkgs` fork from eleven cert-green
auto-merge bundles (`docs/DECISIONS.md:6373`). Per standing project
convention these are **accuracy-comparison artifacts against upstream
ground truth, never merge candidates**. They are not "shipped to
nixpkgs" and not "accepted upstream"; they exist to measure how close the
pipeline's output lands to the human fix.

## Contract-correct refusal (the honest-refusal property)

The lane's trust rests as much on *declining* as on producing. The
clearest evidence is **linux-pam CVE-2025-6020** (pinned base 1.6.1). The
raw upstream master fix `475bd60` fails 14 of 34 hunks against the
pre-fix tree (`docs/DECISIONS.md:9406`): it introduces a new
`secure_opendir()` API, `SECURE_OPENDIR_*` flags, new `polydir_s` fields,
fd-relative signatures and a `pam_sprintf` dependency, none present in the
pinned base. The Patcher (`claude-opus-4-7`, patcher.v4) **refused under
rule 9**, naming those absent constructs and declining rather than
authoring an unfaithful partial that would leave the path-based TOCTOU
callsites intact (`docs/DECISIONS.md:9510`). Outcome recorded as
`no_adaptation_produced`; the scorer abstains because there is nothing to
review.

The correct framing: the pipeline **declined to act** on an input beyond
its safe reach. It produced no patch and no bundle for this CVE. That is
the intended behavior, and it is a stronger signal than a low score would
be, because a fabricated partial patch is worse than an honest refusal.

## Reviewer: two distinct subsystems (do not conflate)

trace has two separately-versioned "Reviewer" artifacts. They are
different models, on different tasks, with unrelated pass/fail states.

**1. Reviewer-LoRA adapter (accept/reject classifier).** Current adapter
`reviewer-lora-v1.10`, a QLoRA fine-tune of `Qwen2.5-Coder-14B-Instruct`,
gate-green on its held-out canary (9/9 canary, 11/11 test,
`docs/REVIEWER_LORA_PILOT.md:178`). One honest limitation remains: on the
zlib CVE-2022-37434 canary the adapter reaches the correct **reject**
verdict but its chain-of-thought hallucinates the absent guard as
present. This was contained by hardening the *gate definition* with a
deterministic `pc_file_grounding` / `pc_role_grounding` falsification
check, not by claiming the model's trace is faithful
(`docs/REVIEWER_LORA_PILOT.md:181`).

**2. Reviewer adaptation-judge prompt (`reviewer.v10` / `v11`).** This is
the frontier-Sonnet prompt that judges semantic *equivalence* on the
adaptation lane, and it currently carries the lane's most honest failure.
On the one bundle where its output can be checked against a trusted
oracle (maxima, below), `reviewer.v10` scored the correct adaptation
**0.0 / not-equivalent** (`docs/DECISIONS.md:9510`). The bug is a
language-generality miss: it applied a per-file, C-translation-unit
reading of its "no unresolved constructs" rule to Common Lisp, flagging
`random-name` as unresolved because it is called in one file and defined
in another, even while acknowledging that a shared `(in-package :maxima)`
resolves the symbol across files. Because the upstream ground-truth fix
has the identical cross-file structure, that rule would reject the ground
truth itself. This is a genuine Reviewer miss, not an oracle defect.

A `reviewer.v11` candidate was drafted to scope the rule to each
language's real symbol-resolution unit. A live three-way eval passed the
maxima true-positive (oracle 1.0) but surfaced harness blockers, and the
verdict was explicit: **do not flip; reviewer.v10 stays the
adaptation-lane default** (`docs/DECISIONS.md:9590`). The harness blockers
were since fixed, and the re-eval is now a single capped `--live` command
**gated on live-spend authorization**; it has not been re-run yet
(`docs/DECISIONS.md:9638`). So the current production state is: one
documented miss on the one case we can check, with a candidate fix that
is drafted, partially validated, and not yet promoted.

## Adaptation-equivalence oracle coverage

Equivalence judgments on the adaptation lane are graded against
**adaptation-equivalence oracles**: referenced, never-vendored,
hash-pinned trusted *human* backports. The registry
(`agents/scorers/adaptation_oracle.py:190`) holds exactly **one** entry:

- **maxima CVE-2024-34490**, `ground_truth_equivalence="equivalent"`,
  `base_relation="same-base"`, provenance a nixpkgs patch at rev
  `08215d1b` (`docs/DECISIONS.md`, `adaptation_oracle.py:174`). The
  registry stores only the label and provenance sha256s, never the oracle
  patch bytes (isolation property, `adaptation_oracle.py:12`).

Two consequences for honesty:

- **N=1.** Any statement about "adaptation-judgment accuracy" is a single
  data point, not a rate. The correct phrasing is "the one case we can
  independently check came back wrong under reviewer.v10," not a failure
  or success percentage.
- **Coverage did not expand.** A cross-distro pivot (Debian/Ubuntu
  oldstable as an oracle source) was run as a bounded pilot and
  **shelved**, yielding **0 additional base-compatible oracles of 3
  deep-screened** (`docs/DECISIONS.md`, 27 July base-compat entry). The
  single Phase-B survivor, libwebp CVE-2023-4863, proved
  base-incompatible with a clean nixpkgs pin: nixpkgs ships pristine
  0.6.1 with no patches, while Debian's backport depends on Debian's own
  `security-fixes.patch` prerequisite, so 5 of 12 hunks fail against the
  nixpkgs base. maxima remains the sole oracle.

## Cost

Cost per merge-ready (auto-merge) bundle: **$0.3772 mean, N=24**
(`docs/COST_REPORT_v1.0.0.md:19`), stable against the earlier $0.3899
mean, N=3 baseline (`docs/COST_REPORT_v0.5.0.md:19`). Total spend on
record: $23.46 across 162 live invocations (`docs/DECISIONS.md:5530`).

**Load-bearing caveat.** Every figure above was measured *before* the
Reviewer bounded auto-retry (`REVIEWER_MAX_ATTEMPTS=2`) landed
(`docs/COST_REPORT_v1.0.0.md:81`). A bundle whose Reviewer retried once
bills a second Reviewer call, so $0.3772 is now a pre-retry-cost floor,
not a current measurement. `trace report throughput` surfaces a Reviewer
retry summary so the extra calls are visible rather than hidden.

The older $0.22/bundle figure that appears in project history measured
Patcher + Reviewer only, before the Reproducer role existed
(`docs/COST_REPORT_v0.5.0.md:22`); it is not comparable to the $0.38
figure and should not be quoted as a regression.

## What trace does not claim

- **Not frontier-parity.** No SOTA or human-parity claim is made or
  supported by this data.
- **Not a broad adaptation-accuracy rate.** Oracle coverage is N=1; the
  adaptation-judge prompt has one documented miss on that one case.
- **Not upstream-merged.** Fork PRs are accuracy artifacts, not merges.
- **Cert-green total is 84/55 as of the 27 July re-run** (certified
  reviewer set), and the overall pilot-ready gate now reads READY
  (`pilot_ready=true`): 0 broken bundles, 0 non-git-provenance evidence
  bundles, with 6 self-declared schema-negative authoring fixtures and 21
  authoring-only pairs excluded (fail-closed) as non-pollution.

The strongest honest statement the evidence supports: on the verbatim
lane the pipeline produces cert-green, signed, replayable bundles at
well-under-a-dollar cost, and on the harder adaptation lane it has
demonstrated one settled equivalence oracle, one contract-correct refusal
on an out-of-reach input, and one clearly-characterized Reviewer miss with
a drafted-but-unpromoted fix. That is a research result, described as one.
