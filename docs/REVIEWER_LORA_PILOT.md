# Reviewer-first LoRA pilot — execution plan

The first fine-tune trace runs. Goal: replace the frontier Reviewer (sonnet) with a
LoRA-tuned open-weight model on the binary accept/reject task, the easier objective,
chosen first ([[trace-finetuning-plan]]). The pilot is also a **pipeline dry-run**:
it de-risks the training harness, the data-format contract, and the eval-fold
plumbing on the track with abundant data and a forgiving objective, before the
starved Authoring track (N=4) where a harness bug is indistinguishable from a data
problem. (Peer-reviewed 2026-06-12.)

## Threshold (resolved — read this first)

The green-light is **50 positives + 25 negatives**, NOT 50 total. (The codex-peer
2026-06-09 plan; the "50 usable" phrasing elsewhere conflated the two.)

| class | have | need | gap |
|---|---|---|---|
| positives | 28 | 50 | **+22** |
| negatives | 25 | 25 | done |

*(B1 bundle 1, postgresql_14 CVE-2026-2003, was attempted 2026-06-12 and DEFERRED, not
banked, pending a Patcher hash-grounding fix for split/`generic.nix` packages. See
DECISIONS 2026-06-12 "B1 attempt: postgresql_14 — DEFERRED".)*

**Reviewer-positives are any VALID bundle**: auto-merge cert-green OR
human-review-valid (the Reviewer's job is accept/reject across all shapes;
auto-merge *refusals* are negatives, not positives). So the +24 gap draws from the
**25 auto-merge-eligible version-bump candidates** in `eval/candidates.jsonl`, cheap,
abundant raw material, unlike the Authoring track's narrow source-backport need. The
positive gap is a **bootstrap-batch** problem (well-documented workflow, ~$5/batch,
batches of 10, checkpoint each batch), not a Scout-harvest problem.

## Why the baseline is NOT frozen yet (deliberate)

The frontier baseline must be frozen over the **held-out fold before training**, but
the fold changes when the +24 positives land, so freezing now would produce an
apples-to-oranges comparison and waste live spend re-running it. **Freeze the
methodology + stratification today; freeze the numbers once the positive set is
final.** (Peer: "deferring the number is correct; freeze the methodology +
stratification rule today; smoke-test the harness now.")

## Baseline-freeze methodology (frozen now; run at N=50)

A baseline you can't reproduce exactly makes the LoRA comparison uninterpretable.
When the positive set is final, freeze ALL of:

1. **Exact Reviewer prompt text** (the `prompts/reviewer.vN.md` SHA, not just the path).
2. **Model id + decoding params**: full model string (e.g. `claude-sonnet-4-5-20250929`),
   plus temperature / top-p / seed (or "unset" recorded explicitly).
3. **Held-out fold row ids**: the exact bundle/example ids in the test fold, so the
   LoRA is evaluated on the *same* rows the frontier baseline saw.
4. **Per-metric breakdown, not just the composite**: record each sub-metric
   (verdict-correctness, evidence-citation, attestation, refusal-class) separately.
   If the frontier Reviewer is already near-ceiling on the composite, the sub-metrics
   are where a LoRA could plausibly have headroom; a composite-only baseline invites a
   null-result surprise.

Both `composite` AND `patch_rate`-equivalent (accept/reject-rate) are tracked, per
the cohort-cadence discipline: a high composite from contract-correct *refusals* is
not the same signal as discrimination accuracy.

## Stratification rule (frozen now)

- Split by **package and CWE-family**, never random row, else the test fold measures
  "saw a sibling in training." Mirrors the exporter's `_split_for` family hashing.
- ≤2 examples per family in any single fold (the negative-minting cap already enforces
  this; positives must match).
- Both classes represented in the held-out fold (a discrimination eval needs reject
  rows too, not just accepts).

## Build order

1. ✅ Exporter (`trace export reviewer`) built + validated (N=20 milestone, 2026-06-10).
2. ✅ Negatives: 25 minted, round-trip clean (`trace mutate reviewer-negative`).
3. **Positives 26 → 50**: bootstrap ~24 reviewer-positive bundles. Batches of 10,
   $5/batch ceiling, stop after 3 consecutive retirements. *(next executable work)*

   **Recon 2026-06-12: the corpus can't fully close this; a harvest pass is also
   needed.** `eval/candidates.jsonl` has only **6 unbundled auto-merge** +
   **~8 unbundled human-review** valid-bundle candidates = ~14 max → even draining it
   lands near **N=40, ~10 short of 50**. So track (c) needs a candidate-harvest pass
   too (version-bump shapes, distinct from the (a) source-backport harvest), runnable
   alongside the bootstrap batch.

   **Cheapest-first ordering: human-review-valid before auto-merge.** A
   human-review-valid bundle is a valid reviewer-positive that needs **no
   reproducer/cert** (just Patcher → Reviewer-accept, 2 live calls), where an
   auto-merge bundle needs the full Builder+Steward+reproducer cert. So bank the
   human-review positives first. Candidate batch **B1** (cheapest reviewer-positives,
   clean patch-release bumps): `postgresql_14` ⏸️ **DEFERRED 2026-06-12** (CVE-2026-2003,
   14.20→14.21, split `14.nix`/`generic.nix` package; Patcher hash-grounding only
   ~1/3 reliable, see Finding below), `samba` (CVE-2025-9640, 4.22.x point release),
   `grafana` (CVE-2026-21722, v12.3.3 patch release). **Screen package shape first**:
   prefer single-file `pkgs/by-name` `package.nix` where `hash` lives in a `src`
   fetcher (like expat); skip split/`generic.nix` packages until the Patcher fix lands.
   Preflight each (the named release must actually contain the fix). Auto-merge
   candidates (chromium, discourse, jruby, openssh_gssapi) are batch B2, costlier (cert).

   **Findings from the postgres attempt (DECISIONS 2026-06-12):**
   - **Patcher hash-grounding fails on split/`generic.nix` packages** (`hash` is a bare
     argument, not `src = fetchFromGitHub { hash = … }`). Grounded correctly ~1/3 runs.
     **Prompt-level fix**: the higher-impact one; unblocks a whole class of
     version-bump candidates. Until it lands, B1 must avoid split packages.
   - **Auto `--fetchzip` mis-substitutes non-dotted tags** (`REL_14_20` vs `14.20`) →
     wrong hash; manual-pin + FOD-verify, or a resolver-side normalization fix.
   - **Bootstrap gotchas:** `bundle finalize` defaults `kind=auto-merge` (pass `--kind
     human-review-required`); do NOT pass `--evidence-path reviewer-attested` (drops the
     schema-required `reproducer.nix` placeholder); sequence is patcher → reviewer →
     finalize then STOP (re-running patcher after a reviewer-accept overwrites the good patch).
4. **Harness smoke-test (parallel, runnable now)**: train a throwaway LoRA on the
   current 51 usable to prove the HF plumbing + data-format contract end-to-end. A
   harness bug found here is free; found at N=50 it's expensive. Not a real result:
   a dry-run.
5. **Freeze the frontier baseline** over the final held-out fold, per the methodology
   above.
6. **Run the pilot**, compare vs the frozen baseline, decide on the Authoring/Patcher
   track next.

## Parallel track (do not serialize behind this)

The Authoring corpus expansion (`docs/AUTHORING_TRAINING.md` step 3) is **search-bound**
(finding source-backport CVEs), while this pilot is **compute/eval-bound**; they do
not contend, so run them in parallel. The source-backport candidate harvest filter is
in `docs/CORPUS.md` § Curation filters → *Source-backport authoring-candidate filter*.

## Readiness gate (the integration/control plane)

`python3 eval/corpus_readiness.py` is the re-runnable quality gate that turns the
fleet's bundle output into a usable dataset (codex peer 2026-06-14: while a fleet
produces volume, one session owns the integration gate). It shells out to
`trace export {reviewer,authoring} --format json` and reports in one place:
positive/negative counts vs the 50+25 threshold (with the gap), train/dev/test split
+ `leakage_check_ok` (the training-validity invariant), an actionable exclusion
breakdown (TRIAGE: attestation-mismatch / no-review, may yield +positives if a
genuine reviewer bundle; STRUCTURAL: dedupe / parser-fail), the authoring count, and a
**baseline-freeze / pilot-ready verdict**. Exit 0 when pilot-ready, 1 otherwise (so it
can gate CI or signal the fleet to stop). `--pos/--neg` override the thresholds; `--json`
for machine output.

Snapshot 2026-06-14: 28/50 positives (gap 22), 25/25 negatives, leakage-free, 11
excluded (8 triage / 3 structural), 4 authoring examples → verdict NOT YET. Run this
before any baseline freeze; freeze only when it prints READY.

Snapshot 2026-07-27: **84 cert-green positives / 55 negatives, verdict READY**
(`pilot_ready=true`, `blocking=[]`). The enumerator now excludes two non-pollution
classes via fail-closed guards: 6 self-declared schema-negative authoring fixtures
(own `expect.json` declares `overall=invalid` + `expected_failure.doc=upstream-ref.json`,
test-asserted-invalid) and 21 authoring-only training pairs, kept visible in the
report. Frozen as **corpus-v2** (`data/reports/reviewer-corpus-2026-07-27-freeze.json`,
139 examples, splits 112/16/11, CVE-disjoint, jsonl `097bd49c…`, commit `f27fc9c`).

---

# Results & findings (v1.0 → v1.10) — research log

> Consolidated narrative of the actual training journey. The chronological detail
> (run IDs, SHAs, prompt SHAs, loss curves, cert URLs) lives in `docs/DECISIONS.md`;
> this section is the readable index into it. Base model throughout:
> `Qwen/Qwen2.5-Coder-14B-Instruct`, QLoRA on HF Jobs (a100-large), adapters at
> `adastracomputing/reviewer-lora-v1.N`. Held-out **canary** = zlib (CVE-2022-37434)
> + jq (CVE-2025-48060 / -33948 / -39979), 9 rows, never trained on.

## The core insight that shaped every version

The Reviewer's binary accept/reject **verdict** got reliable early, but a verdict
without a trustworthy *reason* is not auto-merge-safe. So the gate hardened in lockstep
with the prompt's **required reasoning artifact** for source-backport reviews: a
`## Patch comparison` (PC) section that quotes the actual `+/-` lines and concludes
match/mismatch. Each version closed a way the model could reach a verdict via a
**hallucinated or inconsistent PC trace**: the central failure class, and (per the
unfaithful-chain-of-thought literature, DECISIONS 2026-06-25) a known mid-size-model
limitation rather than a corpus bug.

## Version-by-version

| Ver | Change | Gate canary | Lesson |
|---|---|---|---|
| v1.0–v1.3 | binary task; prompt v1–v4 source-backport rule tightenings (hunk content authoritative over commit prose; rule-8 only on hash-field changes) | — | verdict reliable; reasoning not yet a required artifact |
| v1.4 | — | zlib positive **false-reject** | model quoted identical `+`lines yet wrote `comparison: mismatch` → prompt **v6** PC-verdict consistency rule |
| v1.6 | prompt **v7** two-step extraction | 6/9 | **cross-artifact hallucination**: model filled the patch.diff side from upstream-fix → split into independent `## patch.diff extraction` + `## upstream-fix.patch extraction` |
| v1.7 | — | 7/9 | condition-mutation (`<`→`<=`) + missing-line false-accepts → prompt **v8** critical-token-window (CTW) sub-bullet + token-boundary scorer |
| v1.8 | v8 CTW corpus | — | CTW shipped; canary still imperfect |
| v1.9 | +8 context-reshape **positives** | **zlib positive FIXED**, 9/9 verdicts, gate **FAIL** | reshaping taught CTW-equivalence under context-count differences. But 2 PC-consistency errors remained (PC concludes accept, verdict rejects) |
| v1.10 | prompt **v9** order/placement-sensitive `comparison:` + 4 token-preserving-misplacement negatives + A-full v9 regeneration of the whole SB corpus | 9/9 verdicts, gate **FAIL→PASS** (reconciled) | the 2 remaining failures were **NOT** placement defects: they were absence/role hallucination, so order-sensitivity was orthogonal. Fixed at the **gate definition**, not the model (below) |

## The v1.10 resolution (current state)

`reviewer-lora-v1.10` is the **current adapter**, gate-**green**: canary 9/9, test 11/11
(`data/reports/lora-gate-pilot-v1.10.json`). The 2 persistent zlib PC-consistency
failures (missing-hunk, reversed-hunk) are **unfaithful chain-of-thought**: the model
reaches the correct **reject** verdict but its PC trace hallucinates the absent guard as
present/applied. We reconciled the gate (not the model), grounded in the CoT-faithfulness
+ process-vs-outcome-supervision literature:

- A PC-consistency contradiction is **non-fatal** only when ALL hold: label=negative,
  raw verdict=reject, effective verdict=reject, PC says match/accept, AND a deterministic
  layer falsifies the hallucinated evidence: **`pc_file_grounding`** (quoted line is
  ABSENT from patch.diff) OR **`pc_role_grounding`** (a `+`-quoted "applied" line is
  actually a REMOVED `-` line, the reversed-hunk case). Fatal for any positive, any
  accept, any false-accept, any ungrounded contradiction.
- **Gate guarantee:** no unsafe accepts, no ungrounded/un-role-checked accepts, every PC
  contradiction on a reject is deterministically explained.

This also corrected an earlier mis-read: 2 context-reshape positives that flipped under
v9 were **false-rejects** (the model mis-extracted line order on a narrowed-context
hunk), not genuine defects, dropped from training, not relabeled.

## Operational findings worth keeping

- **The live-reviewer prompt constant was stale** (`reviewer.v4.md`) for the whole
  v1.6–v1.9 line, so v8/v9's CTW + ordered-PC machinery never reached a *generated*
  target, only the export's *system* prompt. Surfaced + fixed during the v1.10 A-full
  regeneration; default bumped to v9 once v1.10 passed.
- **Corpus consistency is a real cost.** Targets generated under mixed prompt versions
  (v2–v4) silently violate a newer prompt's required-section contract. A-full
  regeneration under one prompt is the clean baseline.
- **`NO_CREDITS` mid-run** is a billing stop, not a failure: the adapter only pushes at
  run end, so a killed run leaves no adapter; re-dispatch is idempotent.

## Queued for the next batch

4–6 compound-condition missing/reversed-hunk negatives (long compound guard omitted /
wrong operator / wrong grouping / missing conjunct / check-after-use) to strengthen
generalization on hard multi-subterm guards (the zlib `(len = extra_len - length) <
extra_max` shape). Folded into the next normal training batch, NOT a dedicated run; no
prompt change unless a future failure escapes grounding.

## Held-out compound-guard probe (v1.11 measurability)

Added 2026-07-27. The v1.10 gate is saturated (canary 9/9, test 11/11), and the 5
existing compound-condition negatives (proxychains-ng, libxml2, libxml2-relaxng,
procps) all live in the TRAIN split of the frozen corpus-v2
(`data/reports/reviewer-corpus-2026-07-27-freeze.json`, immutable, 139 examples). A
v1.11 retrain on that corpus would LEARN the compound-guard shape but there was no
HELD-OUT compound example to MEASURE whether it actually generalized, as opposed to
memorizing the five training instances. This probe closes that measurability gap
without touching the frozen corpus or spending any model/API budget.

**Source.** Two families that are demonstrably absent from corpus-v2 train/dev/test
(confirmed by family-normalized diff against `eligible_examples` in the freeze
report, see `tests/eval/test_compound_guard_probe.py`):

- `libwebp` (CVE-2023-4863, the September 2023 zero-day Huffman-table OOB write).
  Compound guard: `if (htree_groups == NULL || code_lengths == NULL ||
  !VP8LHuffmanTablesAllocate(...))` in `ReadHuffmanCodes`, and `if (total_size == 0
  || root_table == NULL) return total_size;` in `VP8LBuildHuffmanTable`.
- `ffmpeg_5` (CVE-2023-49502, the bwdif filter's per-plane bounds check). Compound
  guard: `if (AV_CEIL_RSHIFT(link->w, ...) < 3 || AV_CEIL_RSHIFT(link->h, ...) < 4)`.

Both bundles are trace's own base-valid source backports to the pinned nixpkgs
version (behaviorally green locally 2026-06-28), not a third-party oracle transfer.

**Shape: paired positive + negatives per family, not negatives-only.** A probe that
only ever expects `reject` cannot distinguish genuine compound-guard discrimination
from a model that rejects anything compound-shaped. Each family therefore
contributes a clean, unmutated **positive control** (expected `accept`) alongside its
mutated **negatives** (expected `reject`), minted with the existing `trace mutate
reviewer-negative --mutation condition-drop-conjunct` / `condition-operator-mutation`
tooling against the real added guard line:

| Family | Row | Mutation | Expected |
|---|---|---|---|
| libwebp | clean-positive | — | accept |
| libwebp | drop-codelengths-conjunct | condition-drop-conjunct (drops ` \|\| code_lengths == NULL`) | reject |
| libwebp | drop-alloc-null-conjunct | condition-drop-conjunct (drops ` \|\| root_table == NULL`) | reject |
| ffmpeg_5 | clean-positive | — | accept |
| ffmpeg_5 | drop-height-conjunct | condition-drop-conjunct (drops the `AV_CEIL_RSHIFT(link->h, ...) < 4` conjunct) | reject |
| ffmpeg_5 | off-by-one-width | condition-operator-mutation (`< 3` → `<= 3`) | reject |

6 rows total (2 positive + 4 negative). Bundles live under
`traces/probes/compound-guard/`, a directory `trace export reviewer` never scans (it
only globs `traces/example/` and `traces/negatives/`), so the probe cannot leak into
training regardless of corpus regeneration. Every bundle's `mutation.json` /
`probe.json` carries `"probe": true` and an explicit "excluded from training" note,
mirroring the zlib canary convention.

**Build + score.** `scripts/build_compound_probe.py` assembles the rows with the
same `_build_user_turn` / `_normalize_attr` machinery the regular exporter and
`scripts/build_gate_pilot.py` use, system prompt `prompts/reviewer.v9.md` (the
current default, matching what the v1.10 gate pilot was built against), assistant
turn stripped:

```
python3 scripts/build_compound_probe.py \
  --probes traces/probes/compound-guard \
  --prompt prompts/reviewer.v9.md \
  --out data/probes/compound-guard-probe.jsonl
```

Rows are labeled `split: "canary"` so `eval/score_gate_pilot.py` applies its full
canary-grade treatment with **zero scorer changes**: mandatory correctness plus the
PC-consistency / `pc_file_grounding` / `pc_role_grounding` checks. This is a reused
label, not a claim that this is the v1.10 gate's zlib/jq canary; the probe is always
scored as its own isolated file, never merged into the real gate-pilot JSONL. Score
at v1.11 eval time with:

```
python3 eval/score_gate_pilot.py \
  --pilot data/probes/compound-guard-probe.jsonl \
  --responses <v1.11-responses.jsonl> \
  --out data/reports/compound-guard-probe-v1.11.json
```

**Read the result as three separate numbers, not one accuracy.** Label the run
"unseen-family compound-guard probe, n=6" and report:

1. **Raw verdict accuracy**: `canary_correct / canary_total` from the report
   summary (6/6 in the harness sanity-check with a synthetic all-correct response
   set; see `tests/eval/test_compound_guard_probe.py` for the row-shape
   verification, not a model result).
2. **Paired-positive false-reject rate**: among the 2 positive rows, how many
   `details.canary` entries have `label: positive` and `outcome: false_reject`. This
   is the control: a model that rejects the clean guard alongside its mutated
   siblings is not discriminating, it is pattern-matching "compound guard → reject".
3. **Grounding/composite diagnostics, reported separately**: `canary_pc_file_
   grounding_errors`, `canary_pc_role_grounding_errors`, and
   `canary_pc_consistency_fatal` from the same report. These measure whether a
   correct reject verdict is backed by a faithful PC trace, independent of whether
   the raw verdict was correct.

**This is a first measurability signal, not a generalization claim.** Two families
and 6 rows establish that v1.10-vs-v1.11 comparison on unseen compound guards is now
possible; they are not enough to claim broad generalization either way. A stronger
claim needs a third unseen family and more paired cases, queued alongside the next
normal compound-condition training batch above.

## v1.11 retrain preregistration (2026-07-28)

**Config.** Base model `Qwen/Qwen2.5-Coder-14B-Instruct` pinned at revision
`aedcc2d42b622764e023cf882b6652e646b95671` (unchanged from v1.10, per
`lora/hf_job.py`). Prompt `prompts/reviewer.v9.md`, held constant with v1.10.
Split manifest `data/splits/reviewer-v1.8.json`, held constant with v1.10.
v1.10 trained on 128 eligible examples (107 train / 10 dev / 11 test, 79
positive / 49 negative) under this identical v9 + reviewer-v1.8 config.
v1.11 trains on 134 eligible examples (113 train / 10 dev / 11 test, 80
positive / 54 negative, family-leakage-free). The true intervention is
**+6 train examples (+1 positive, +5 negative)**; dev and test are
UNCHANGED at 10/11. This is a small, negative-heavy corpus addition, not a
large data increase. `MAX_STEPS=203`, `gradient_accumulation_steps=4`,
`seed=42`, giving approximately 7.19 effective epochs over the 113-example
train split.

The exact added examples (v1.10 → v1.11), reconstructed from git history:

- **+1 positive:** libarchive CVE-2026-15028 (source-backport adaptation).
- **+5 negatives: all compound-condition**, added in commit `c4d4bd5`
  (2026-06-25, "5 compound-condition Reviewer negatives (v1.11 queue)"), which
  postdates the v1.10 training run (v1.10 corpus had 0 compound-condition
  negatives). They are the SAME mutation class as the held-out probe
  (`condition-drop-conjunct` / `condition-operator-mutation`), on three TRAIN
  families disjoint from the probe's two held-out families:
  proxychains-ng CVE-2025-34451 (drop-conjunct + operator-mutation),
  libxml2_13 CVE-2025-6170 (drop-conjunct), libxml2_13 CVE-2026-0989
  (operator-mutation), procps CVE-2023-4016 (drop-conjunct).

So the +5 added negatives ARE the compound-guard class (5/5), which is why this
is framed as a targeted compound-guard hard-negative intervention: the probe
measures cross-family transfer of exactly the mutation class the added
negatives teach, not memorization (train and probe families are disjoint).

**Contract-drift exclusion.** One otherwise-eligible target, maxima
CVE-2024-34490 (bundle `c3ad8fadc690f28e`, a train negative added 2026-07-27),
carries a `## Equivalence assessment` section. That section was introduced in
reviewer.v10 (adaptation lane); reviewer.v9 defines only `## Verdict`,
`## Reasoning`, and `## Patch comparison` and never emits it. Pairing that
v10-shaped target with the v9 system prompt is contract drift, so
`lora/submit_hf_job_v1.11.sh` drops it via a v9-foreign-heading filter (guarded
to fail loudly if it ever matches more than this one bundle) before writing the
splits. It is an adaptation-lane rejection, NOT a compound-guard negative, so
its removal does not touch the +5 compound-guard delta. This keeps the v9
retrain a clean one-variable comparison; the alternative (switch the whole
prompt to v10) was rejected because it would change task framing alongside
corpus.

The only variable between v1.10 and v1.11 is corpus size. The freeze-faithful
alternative (default split manifest + prompt v2) was considered and rejected:
it changes prompt and split simultaneously with corpus, so any resulting delta
could not be attributed to corpus growth alone.

**Count reconciliation.** The corpus-v2 freeze (above) reports 139 total / 84
positive because it used default splits with no canary carve-out. The
reviewer-v1.8 manifest used here holds out 4 gate-pilot canary bundles (zlib
CVE-2022-37434, jq CVE-2025-48060, jq CVE-2026-33948, jq CVE-2026-39979, all
positive base bundles), so 139 = 134 trained + 4 gate-pilot canary (held out)
+ 1 maxima (v10-shaped target excluded under v9, see Contract-drift exclusion
above) and 84 positive = 80 trained + 4 canary positives (maxima is a negative,
so positive counts are unchanged). No examples are silently lost between the two
counts; they describe the same corpus under two split manifests, minus one
prompt-target-mismatched row.

**Pre-registered expected outcomes.** This is a small, negative-heavy
intervention (+6 train examples, 5 of which are negative), so a large probe
gain is NOT the expected outcome: a jump from 0/6 to 6/6 on the
compound-guard probe would itself be a surprising result worth scrutinizing
rather than taking at face value. The probe instead measures whether even
this small corpus shift moves held-out compound-guard behavior at all, in
either direction. The compound-guard probe
(`data/probes/compound-guard-probe.jsonl`) is scored on BOTH v1.10 (control,
`submit_hf_gate_pilot_v1.10_control.sh`, run first) and v1.11
(`submit_hf_gate_pilot_v1.11.sh`) against the identical input. Read the delta
as follows:

| v1.10 control | v1.11 | Interpretation |
|---|---|---|
| fails | passes | improvement: more corpus measurably helped |
| passes (6/6) | passes (6/6) | probe already saturated; v1.11 shows non-regression only, not a gain |
| fails | fails identically | no measurable gain from the added corpus |
| passes | fails | regression: investigate before promoting v1.11 |

Do not report a v1.11 6/6 result as an improvement unless the v1.10 control
scores lower on the same input. A v1.11 score read in isolation says nothing
about whether the retrain helped.

**Failure signatures to report**, independent of the raw pass/fail:

- **Paired-positive false-reject rate** (primary rejection-bias signal): among
  the 2 clean-positive probe rows, how many come back `outcome: false_reject`.
  A model that rejects the clean guard alongside its mutated siblings is
  pattern-matching "compound guard → reject", not discriminating.
- **Raw verdict vs `effective_verdict`**: report both. A grounding override
  (raw `accept` flipped to `effective_verdict: reject` by deterministic
  patch.diff-side grounding) must NOT count as a model success: it is the
  gate's safety net catching a hallucinated accept, not the model getting the
  call right.
- **Results by `mutation_type`**: `condition-operator-mutation` (off-by-one)
  and `condition-drop-conjunct` (dropped conjunct) are reported separately,
  not pooled, since they may fail at different rates.
  **Mutation-asymmetry pre-registration**, exactly three claims, no more:
  (1) dropped-conjunct transfer is measured across TWO unseen families
  (libwebp CVE-2023-4863 and ffmpeg_5 CVE-2023-49502 each contribute
  `condition-drop-conjunct` rows); (2) operator-mutation behavior is measured
  on ONE unseen family only (ffmpeg_5 CVE-2023-49502), n=1; (3) NO
  operator-mutation cross-family transfer claim will be made from this probe:
  a single-family, n=1 result cannot support one.
- **Parse/schema failures**: any response that does not yield a parseable
  verdict is reported as its own category, not folded into false-reject or
  false-accept counts.
- **PC-consistency and file/role grounding**: `canary_pc_consistency_fatal`,
  `canary_pc_file_grounding_errors`, and `canary_pc_role_grounding_errors`
  from the same report, so a correct verdict backed by a hallucinated PC trace
  is visible even when the raw verdict is right.
- **Family-level behavior**: report libwebp and ffmpeg_5 separately. One
  family passing all 3 of its rows while the other fails is NOT cross-family
  transfer: it is a single-family result and should be labeled as such.

**Preregistration guards.**

- The test split and the compound-guard probe are each evaluated ONCE, after
  checkpoint selection. Neither selects hyperparameters or checkpoints.
- Dev is model-selection data and is reported separately from test; dev
  results do not substitute for the test or probe numbers above.
- Promotion to "current adapter" requires: zero regression on the existing
  gate (canary 9/9, test 11/11, `pc_consistency_fatal == 0`, matching the
  v1.10 bar) AND no raw false accept or false reject on the probe AND no parse
  failures AND no grounding or PC-consistency override needed to reach 6/6 on
  the probe. A 6/6 that only passes after invoking the grounding-explained
  reconciliation path does not meet the promotion bar.
- If v1.11 fails the probe and we subsequently tune against it, the probe
  becomes dev data by definition and a NEW family-disjoint probe is required
  before the next measurability claim.
- The 26-row merged inference input (gate pilot + probe) is bound by SHA-256:
  the dispatch script computes `MERGED_SHA256` and passes it as
  `EXPECTED_INPUT_SHA256` to the job, which aborts with `RuntimeError` if the
  mounted `gate-pilot.jsonl` does not hash-match: the shared dataset filename
  is mutable, so this binds the job to the exact 26-row file built at dispatch
  time. Each arm writes raw model responses to a distinct immutable path
  (control → `gate_pilot_responses/corpus-v2-control/responses.jsonl`, v1.11 →
  `gate_pilot_responses/corpus-v2-eval/responses.jsonl`), so neither run
  overwrites the original v1.10 20-row gate responses at
  `gate_pilot_responses/responses.jsonl`. Dispatch provenance
  (`exports/reviewer-v1.11/control-dispatch-provenance.json` and
  `eval-dispatch-provenance.json`) records dataset revision, merged-file
  sha256, adapter repo, and response count/path for both arms; the job itself
  prints the response-file sha256 at push time for cross-check. Training
  dispatch provenance (`exports/reviewer-v1.11/dispatch-provenance.json`)
  records train/dev/test/full-export sha256.

**Assistant-target audit.** All 135 v1.11 training targets are v9-shaped: all
135 carry Verdict / Reasoning / Findings / Cited evidence / Cross-family
attestation sections; the 62 source-backport rows additionally carry
`patch.diff` extraction, `upstream-fix.patch` extraction, and a Patch
comparison section; exactly one row (maxima CVE-2024-34490) carries an
Equivalence assessment section, a coherent v9 adaptation-equivalence result.
No later-version-only sections appear anywhere in the export: v9 is the
latest reviewer prompt, so there is nothing later to leak in.

**Absence assertion.** All 6 probe records (both families, matched by
user-turn content) are absent from every v1.11 training input. Confirmed by
local dry export (2026-07-28, prompt v9 + split reviewer-v1.8): 0 hits for
`CVE-2023-4863` or `CVE-2023-49502` anywhere in the 135-row eligible export,
not just the 114-row train split.
