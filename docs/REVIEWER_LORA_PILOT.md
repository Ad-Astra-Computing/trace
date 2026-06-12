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
| positives | 26 | 50 | **+24** |
| negatives | 25 | 25 | done |

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
   clean patch-release bumps): `postgresql_14` (CVE-2026-2003, 14.20→14.21 — **preflight GREEN
   2026-06-12**: postgresql.org/security confirms fixed in 14.21, affected before
   14.21, oidvector memory disclosure), `samba` (CVE-2025-9640, 4.22.x point release,
   passthru_tests=yes), `grafana` (CVE-2026-21722, v12.3.3 patch release). Preflight
   each (CLAUDE.md bundle-bootstrap step 1: the named release must actually contain
   the fix commit) before staging. Auto-merge candidates (chromium, discourse, jruby,
   openssh_gssapi) are batch B2 — costlier (cert), do after B1.
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
