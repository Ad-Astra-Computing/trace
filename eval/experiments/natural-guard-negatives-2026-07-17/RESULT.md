# Natural-guard hard-negative retrain — negative result (2026-07-17)

Quality-over-quantity follow-on to the 2026-07-16 mechanical operator-flip arc
(which regressed the reviewer to 0.618). Hypothesis: a few *natural* guard
negatives (real historical-vulnerable guards substituted back into the patch,
not synthetic operator flips) would teach the char-level guard comparison the
LoRA misses without the negative transfer the mechanical flips caused.

## Method

- Minted 3 natural guard negatives, each frontier-validated (`claude-sonnet-4-5`,
  reviewer.v6) as a clear **reject**:
  - `CVE-2022-46908` sqlite — compares the wrong allow-list arg (`zA1` not `zA2`)
  - `CVE-2025-34451` proxychains-ng — length check gated on SOCKS5 only
  - `CVE-2026-7598` libssh2 — addition can integer-overflow before the compare
  - (a 4th candidate, `CVE-2026-33948` jq, was frontier-**accepted** → dropped)
- Retrained Qwen2.5-Coder-14B QLoRA from the **baseline seed/config** (seed 42,
  MAX_STEPS 150), dataset `reviewer-lora-data-v2-bigfold-nat` (train 94 / dev 11).
- Evaluated on the **identical** 34-fold as baseline (`gate-pilot.jsonl`).

## Result — does NOT beat baseline+lint

| | Baseline + lint | Natural-guard + lint |
|---|---|---|
| Composite substance | 0.853 (29/34) | 0.853 (29/34) — **tie** |
| False-accept (post-lint) | 5 | 4 |
| **False-reject** | **0** | **1** |

- The 3 targeted `source-backport-condition-mutation` false-accepts
  (coreutils / busybox / bzip2) **all persist** — 0/3 fixed.
- **busybox inversion**: the model false-rejects the busybox *positive*
  (`CVE-2025-60876`) while still false-accepting the busybox *negative* —
  worse calibration, breaking the baseline's zero-false-reject invariant.

## Decision

Reverted. Baseline LoRA + deterministic metadata lint (composite 0.853,
0 false-reject) remains the shippable Reviewer. These 3 artifacts are archived
here (excluded from `trace export reviewer`, which only scans `traces/`).
Minter kept as reusable tooling: `lora/mint_natural_guard_negatives.py`.

**Lesson (narrow):** 3 natural contrastive examples were insufficient and caused
negative transfer. Consistent with the data-scale/diversity hypothesis; does not
prove scaling solves char-level comparison. **Production conclusion (stronger):**
under the current corpus, learned semantic guard comparison is not reliable
enough to auto-gate — route semantic guard discrepancies to frontier review.
