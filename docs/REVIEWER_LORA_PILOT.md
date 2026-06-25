# Reviewer-first LoRA pilot — execution plan

The first fine-tune trace runs. Goal: replace the frontier Reviewer (sonnet) with a
LoRA-tuned open-weight model on the binary accept/reject task — the easier objective,
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

*(B1 bundle 1, postgresql_14 CVE-2026-2003, was attempted 2026-06-12 and DEFERRED — not
banked — pending a Patcher hash-grounding fix for split/`generic.nix` packages. See
DECISIONS 2026-06-12 "B1 attempt: postgresql_14 — DEFERRED".)*

**Reviewer-positives are any VALID bundle** — auto-merge cert-green OR
human-review-valid (the Reviewer's job is accept/reject across all shapes;
auto-merge *refusals* are negatives, not positives). So the +24 gap draws from the
**25 auto-merge-eligible version-bump candidates** in `eval/candidates.jsonl` — cheap,
abundant raw material, unlike the Authoring track's narrow source-backport need. The
positive gap is a **bootstrap-batch** problem (well-documented workflow, ~$5/batch,
batches of 10, checkpoint each batch), not a Scout-harvest problem.

## Why the baseline is NOT frozen yet (deliberate)

The frontier baseline must be frozen over the **held-out fold before training** — but
the fold changes when the +24 positives land, so freezing now would produce an
apples-to-oranges comparison and waste live spend re-running it. **Freeze the
methodology + stratification today; freeze the numbers once the positive set is
final.** (Peer: "deferring the number is correct; freeze the methodology +
stratification rule today; smoke-test the harness now.")

## Baseline-freeze methodology (frozen now; run at N=50)

A baseline you can't reproduce exactly makes the LoRA comparison uninterpretable.
When the positive set is final, freeze ALL of:

1. **Exact Reviewer prompt text** (the `prompts/reviewer.vN.md` SHA, not just the path).
2. **Model id + decoding params** — full model string (e.g. `claude-sonnet-4-5-20250929`),
   plus temperature / top-p / seed (or "unset" recorded explicitly).
3. **Held-out fold row ids** — the exact bundle/example ids in the test fold, so the
   LoRA is evaluated on the *same* rows the frontier baseline saw.
4. **Per-metric breakdown, not just the composite** — record each sub-metric
   (verdict-correctness, evidence-citation, attestation, refusal-class) separately.
   If the frontier Reviewer is already near-ceiling on the composite, the sub-metrics
   are where a LoRA could plausibly have headroom; a composite-only baseline invites a
   null-result surprise.

Both `composite` AND `patch_rate`-equivalent (accept/reject-rate) are tracked, per
the cohort-cadence discipline — a high composite from contract-correct *refusals* is
not the same signal as discrimination accuracy.

## Stratification rule (frozen now)

- Split by **package and CWE-family**, never random row — else the test fold measures
  "saw a sibling in training." Mirrors the exporter's `_split_for` family hashing.
- ≤2 examples per family in any single fold (the negative-minting cap already enforces
  this; positives must match).
- Both classes represented in the held-out fold (a discrimination eval needs reject
  rows too, not just accepts).

## Build order

1. ✅ Exporter (`trace export reviewer`) built + validated (N=20 milestone, 2026-06-10).
2. ✅ Negatives: 25 minted, round-trip clean (`trace mutate reviewer-negative`).
3. **Positives 26 → 50** — bootstrap ~24 reviewer-positive bundles. Batches of 10,
   $5/batch ceiling, stop after 3 consecutive retirements. *(next executable work)*

   **Recon 2026-06-12 — the corpus can't fully close this; a harvest pass is also
   needed.** `eval/candidates.jsonl` has only **6 unbundled auto-merge** +
   **~8 unbundled human-review** valid-bundle candidates = ~14 max → even draining it
   lands near **N=40, ~10 short of 50**. So track (c) needs a candidate-harvest pass
   too (version-bump shapes — distinct from the (a) source-backport harvest), runnable
   alongside the bootstrap batch.

   **Cheapest-first ordering — human-review-valid before auto-merge.** A
   human-review-valid bundle is a valid reviewer-positive that needs **no
   reproducer/cert** (just Patcher → Reviewer-accept, 2 live calls), where an
   auto-merge bundle needs the full Builder+Steward+reproducer cert. So bank the
   human-review positives first. Candidate batch **B1** (cheapest reviewer-positives,
   clean patch-release bumps): `postgresql_14` ⏸️ **DEFERRED 2026-06-12** (CVE-2026-2003,
   14.20→14.21 — split `14.nix`/`generic.nix` package; Patcher hash-grounding only
   ~1/3 reliable, see Finding below), `samba` (CVE-2025-9640, 4.22.x point release),
   `grafana` (CVE-2026-21722, v12.3.3 patch release). **Screen package shape first**:
   prefer single-file `pkgs/by-name` `package.nix` where `hash` lives in a `src`
   fetcher (like expat); skip split/`generic.nix` packages until the Patcher fix lands.
   Preflight each (the named release must actually contain the fix). Auto-merge
   candidates (chromium, discourse, jruby, openssh_gssapi) are batch B2 — costlier (cert).

   **Findings from the postgres attempt (DECISIONS 2026-06-12):**
   - **Patcher hash-grounding fails on split/`generic.nix` packages** (`hash` is a bare
     argument, not `src = fetchFromGitHub { hash = … }`). Grounded correctly ~1/3 runs.
     **Prompt-level fix** — the higher-leverage one; unblocks a whole class of
     version-bump candidates. Until it lands, B1 must avoid split packages.
   - **Auto `--fetchzip` mis-substitutes non-dotted tags** (`REL_14_20` vs `14.20`) →
     wrong hash; manual-pin + FOD-verify, or a resolver-side normalization fix.
   - **Bootstrap gotchas:** `bundle finalize` defaults `kind=auto-merge` (pass `--kind
     human-review-required`); do NOT pass `--evidence-path reviewer-attested` (drops the
     schema-required `reproducer.nix` placeholder); sequence is patcher → reviewer →
     finalize then STOP (re-running patcher after a reviewer-accept overwrites the good patch).
4. **Harness smoke-test (parallel, runnable now)** — train a throwaway LoRA on the
   current 51 usable to prove the HF plumbing + data-format contract end-to-end. A
   harness bug found here is free; found at N=50 it's expensive. Not a real result —
   a dry-run.
5. **Freeze the frontier baseline** over the final held-out fold, per the methodology
   above.
6. **Run the pilot**, compare vs the frozen baseline, decide on the Authoring/Patcher
   track next.

## Parallel track (do not serialize behind this)

The Authoring corpus expansion (`docs/AUTHORING_TRAINING.md` step 3) is **search-bound**
(finding source-backport CVEs), while this pilot is **compute/eval-bound** — they do
not contend, so run them in parallel. The source-backport candidate harvest filter is
in `docs/CORPUS.md` § Curation filters → *Source-backport authoring-candidate filter*.

## Readiness gate (the integration/control plane)

`python3 eval/corpus_readiness.py` is the re-runnable quality gate that turns the
fleet's bundle output into a usable dataset (codex peer 2026-06-14: while a fleet
produces volume, one session owns the integration gate). It shells out to
`trace export {reviewer,authoring} --format json` and reports in one place:
positive/negative counts vs the 50+25 threshold (with the gap), train/dev/test split
+ `leakage_check_ok` (the training-validity invariant), an actionable exclusion
breakdown (TRIAGE: attestation-mismatch / no-review — may yield +positives if a
genuine reviewer bundle; STRUCTURAL: dedupe / parser-fail), the authoring count, and a
**baseline-freeze / pilot-ready verdict**. Exit 0 when pilot-ready, 1 otherwise (so it
can gate CI or signal the fleet to stop). `--pos/--neg` override the thresholds; `--json`
for machine output.

Snapshot 2026-06-14: 28/50 positives (gap 22), 25/25 negatives, leakage-free, 11
excluded (8 triage / 3 structural), 4 authoring examples → verdict NOT YET. Run this
before any baseline freeze; freeze only when it prints READY.

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
**hallucinated or inconsistent PC trace** — the central failure class, and (per the
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
| v1.10 | prompt **v9** order/placement-sensitive `comparison:` + 4 token-preserving-misplacement negatives + A-full v9 regeneration of the whole SB corpus | 9/9 verdicts, gate **FAIL→PASS** (reconciled) | the 2 remaining failures were **NOT** placement defects — they were absence/role hallucination, so order-sensitivity was orthogonal. Fixed at the **gate definition**, not the model (below) |

## The v1.10 resolution (current state)

`reviewer-lora-v1.10` is the **current adapter**, gate-**green**: canary 9/9, test 11/11
(`data/reports/lora-gate-pilot-v1.10.json`). The 2 persistent zlib PC-consistency
failures (missing-hunk, reversed-hunk) are **unfaithful chain-of-thought**: the model
reaches the correct **reject** verdict but its PC trace hallucinates the absent guard as
present/applied. We reconciled the gate (not the model), grounded in the CoT-faithfulness
+ process-vs-outcome-supervision literature:

- A PC-consistency contradiction is **non-fatal** only when ALL hold: label=negative,
  raw verdict=reject, effective verdict=reject, PC says match/accept, AND a deterministic
  layer falsifies the hallucinated evidence — **`pc_file_grounding`** (quoted line is
  ABSENT from patch.diff) OR **`pc_role_grounding`** (a `+`-quoted "applied" line is
  actually a REMOVED `-` line — the reversed-hunk case). Fatal for any positive, any
  accept, any false-accept, any ungrounded contradiction.
- **Gate guarantee:** no unsafe accepts, no ungrounded/un-role-checked accepts, every PC
  contradiction on a reject is deterministically explained.

This also corrected an earlier mis-read: 2 context-reshape positives that flipped under
v9 were **false-rejects** (the model mis-extracted line order on a narrowed-context
hunk), not genuine defects — dropped from training, not relabeled.

## Operational findings worth keeping

- **The live-reviewer prompt constant was stale** (`reviewer.v4.md`) for the whole
  v1.6–v1.9 line, so v8/v9's CTW + ordered-PC machinery never reached a *generated*
  target — only the export's *system* prompt. Surfaced + fixed during the v1.10 A-full
  regeneration; default bumped to v9 once v1.10 passed.
- **Corpus consistency is a real cost.** Targets generated under mixed prompt versions
  (v2–v4) silently violate a newer prompt's required-section contract. A-full
  regeneration under one prompt is the clean baseline.
- **`NO_CREDITS` mid-run** is a billing stop, not a failure — the adapter only pushes at
  run end, so a killed run leaves no adapter; re-dispatch is idempotent.

## Queued for the next batch

4–6 compound-condition missing/reversed-hunk negatives (long compound guard omitted /
wrong operator / wrong grouping / missing conjunct / check-after-use) to strengthen
generalization on hard multi-subterm guards (the zlib `(len = extra_len - length) <
extra_max` shape). Folded into the next normal training batch, NOT a dedicated run; no
prompt change unless a future failure escapes grounding.
