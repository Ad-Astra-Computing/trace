# Authoring training data — teaching an OSS model to fix CVEs, not copy fixes

**Goal.** Fine-tune an open-weight model (Qwen2.5-Coder, per the finetuning plan)
to AUTHOR CVE source-fixes, so production doesn't need opus. The whole point of
the corpus is to be that training set.

**The distinction that matters (Jason, 2026-06-12).** The cert-green
source-backport bundles SUPPLY the upstream fix to the Patcher (`upstream-fix.patch`),
which transcribes it. As training data that teaches *copying*. To teach
*authoring* — so the model needs neither opus nor the upstream commit — the
training example must be:

> **input** = CVE finding (vulnerability only) + the PRE-fix source + package.nix
> **label** = the correct fix (= the validated upstream fix)

The cert-green bundles become the **answer key**, not the input.

**Authoring is learnable — proven.** `eval/author_blind_eval.py` gives a model
ONLY the CVE symptom + the pre-fix source window (no upstream fix) and grades the
authored diff vs upstream. On the 4 cert-green backports: **2 exact** (proxychains:
remove the `RS_PT_SOCKS5` gate; bzip2: `>= MAX` → `>= MAX-1`), **2 differs**
(libxmp + graphite2 authored a different valid-looking fix — graphite2 wrote its
own `slotat` bounds-check with `DIE` instead of upstream's `nullptr`+status). So a
model derives these fixes from the vulnerability; it does not need the answer.

## Grader (peer-reviewed 2026-06-12) — tiered, for CANDIDATES only

Training **labels need no grading** — for a cert-green bundle the label IS the
validated upstream fix. The rubric applies only to model-authored candidates
(eval / RL / rejection-sampling expansion):

1. **reproducer red→green = mandatory gate.** Fail → auto-reject. (Strengthen the
   reproducers with boundary-variant inputs — a narrow one-PoC reproducer can pass
   a subtly-wrong fix; the bzip2 `>= MAX-1` case wants an off-by-one boundary fuzz.)
2. **green + upstream-semantically-equivalent = gold** → promote to training.
3. **green + differs from upstream = needs-review** → LLM-judge (or human) asks the
   specific question "does this close *every* path the upstream fix closed?" This is
   where the libxmp-partial failure hides; never auto-promote it.

Do NOT hard-require upstream-match (overfits to upstream's idiom, punishes
legitimately-different-correct fixes). Do NOT treat behavioral-pass as gold (rewards
plausible-but-subtly-wrong fixes). Gold = behavioral-pass AND upstream-equivalent.

## Leakage traps — ranked (the corpus is full of them)

1. **Cross-task leakage (architectural).** If `backport-package` keeps
   `upstream-fix.patch` as INPUT and the SAME CVE is an `author-from-vuln` example,
   the model has seen the answer key. **Partition by CVE: each CVE → exactly one
   task; held-out CVEs excluded from both.**
2. **CVE summary describing the remediation.** The finding must describe the
   vulnerability (trigger, what's wrong), NEVER the fix. The exporter scrubs against
   the ACTUAL fix, not just generic remediation phrasing: `_fix_symbols()` extracts
   the symbols the fix changes (distinctive identifiers on any +/- line, union of
   both sides; plus numeric literals that MOVED between the removed/added lines —
   symmetric difference, so an unchanged buffer-size constant the vuln legitimately
   names is kept). `_scrub_summary()` drops any sentence naming a fix symbol or
   remediation phrase; `_run_authoring()` then HARD-EXCLUDES the bundle if any fix
   symbol survives or the summary scrubs to empty. Verified: proxychains's
   `RS_PT_SOCKS5`, graphite2's `slotat`, bzip2's `BZ_MAX_HANDLED_BLOCKS` no longer
   appear in any input. **Residual classes the heuristic can't name** (peer review
   2026-06-12, non-blocking — summaries describe the bug, not the patch): a fix that
   moves only a single-digit literal (`>= MAX` → `>= MAX - 1`; the `1` is too generic
   to scrub on, but the touched identifier usually carries the tell); a genuinely
   distinctive ≤5-char all-lowercase identifier; paraphrased remediation that names
   no symbol. `manifest.json.low_signal_bundles` flags any fix that produced 0 scrub
   symbols so "nothing to scrub" is visibly distinct from "scrubbed clean."
3. **Upstream's regression test, co-located in the bundle.** The fix commit usually
   adds a test encoding the post-fix boundary (where `>= MAX-1`'s constant leaks).
   Exclude any file the fix commit added under a test/fixture dir. NOTE: this is
   exactly what `trace backport-fixtures` extracts — fine for the reproducer, but it
   must NOT be in an authoring example's input.
4. **Reproducer derived from upstream's test** if it embeds the expected assertion.
5. **Post-fix source masquerading as the vuln source** — snapshot the genuine PRE-fix
   tree (the fix commit's parent), don't revert the diff (leaves fix-added comments).
6. **package.nix tells** — already-bumped version, changelog/comment naming the fix
   commit, patch-list naming.
7. **VCS metadata** — commit message, blame, `*-fix.patch` filenames in the bundle.

## Held-out eval (the blind-eval doubles as it)

- Split by **package and CWE-family**, not random CVE (else you measure "saw a
  sibling CVE in training").
- Prefer **recent/obscure** CVEs for the held-out fold to dodge Qwen pretraining
  contamination (old famous CVE fixes are in pretraining and inflate the score).
- Report BOTH diff-vs-upstream match rate AND reproducer-pass rate — they diverge
  exactly on the interesting cases.

## Build order

1. ✅ `eval/author_blind_eval.py` — the blind-authoring eval / held-out grader.
2. ✅ `trace export authoring` — emits `(CVE-vuln-only + pre-fix source) → upstream
   source fix` pairs from the cert-green source-backport bundles, with the
   fix-symbol scrub + hard leakage gate above. N=4 today (all `train` until the
   corpus is big enough to hold a package/CWE-family fold out). Per-bundle pair is
   cached to `<bundle>/authoring-example.json` (sha-pinned → offline, reproducible).
3. Reproducer-gated candidate expansion — author blind, gate on red→green, judge the
   differs, promote gold. Grows the corpus beyond hand-curated bundles.
4. Reviewer-first LoRA pilot at N≥50 usable (per the finetuning plan), then Patcher.
