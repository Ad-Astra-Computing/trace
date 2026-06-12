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
   vulnerability (trigger, what's wrong), NEVER the fix. Strip remediation language
   (`author_blind_eval.py` does this with `_REMEDIATION_RE`).
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
2. `trace export patcher --authoring` — emit `(CVE + pre-fix source + package.nix)
   → fix` pairs from the cert-green bundles, with the leakage partition + scrubbing
   above. (The existing `trace export reviewer` is the template.)
3. Reproducer-gated candidate expansion — author blind, gate on red→green, judge the
   differs, promote gold. Grows the corpus beyond hand-curated bundles.
4. Reviewer-first LoRA pilot at N≥50 usable (per the finetuning plan), then Patcher.
