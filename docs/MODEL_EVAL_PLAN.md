# trace — Open-Weight Model Eval and Fine-Tune Plan

Status: draft
Scope: research plan for open-weight model evaluation and fine-tuning within `trace`

---

## Goal

Determine whether an open-weight model can replace frontier models for one or more `trace` role contracts, starting with `Patcher`, by matching or approaching frontier performance on the frozen replay corpus and human-review outcomes.

This is not a project to make an OSS model "as good as Claude on everything." It is a project to see whether an open-weight model can become good enough on `trace`'s narrow, structured tasks.

---

## Initial scope

Start with one role only:

- `Patcher` first
- `Reviewer` second only if `Patcher` shows promise

Do not train models for:

- `Scout`
- `Cartographer`
- `UpstreamRefResolver`
- `Steward`

Those should remain deterministic or mostly deterministic.

---

## Terminology

Definitions used throughout this plan. These align with SPEC §4, SPEC §5a, `docs/DECISIONS.md`, and the replay runner semantics wired up through commit `f4e9bae`.

- **Replay corpus** / **frozen eval corpus** — the 51 CVE entries in `eval/corpus.json`, frozen 2026-04-23 at commit `f4e9bae`. This is the held-out evaluation bench. It is NEVER used as training data at any phase.

- **Train / dev / test** — splits of a SEPARATE SFT pool drawn from historical nixpkgs CVEs that do not share a `cve_id` with any entry in the frozen corpus. The separation is enforced by the training data-loader: any overlap rejects the training example at load time and is logged.

- **Scorer** — one of the six Patcher-facing measurement functions: (1) schema-valid output, (2) upstream-ref compliance, (3) hash-verifiability, (4) unrelated-file touch rate, (5) minimality, (6) historical-fix similarity. Run by the Patcher replay runner against frozen replay outputs. Two composite metrics derived from the set: **merge-ready rate** (per-bundle contract-honour score) and **patch_rate** (corpus-level productivity score). See "Model-specific metrics" below for definitions.

- **Dispatch guards** — the two advisory-only entries in the 8-entry Patcher inner-loop subset (`python314` CVE-2025-4517, `xen` CVE-2025-58147). Patcher is never invoked on `ineligible-cherry-pick-required` inputs; these entries verify the pipeline correctly routes them to the advisory-only path WITHOUT invoking Patcher. They are **excluded from the Patcher scorer denominator**; if a Patcher output appears for one of them, that is a dispatch bug to flag, not a Patcher quality signal.

- **Model baseline** — a specific frontier model used as the quality ceiling for comparison. `claude-opus-4-7` is the provisional Patcher bring-up model baseline.

- **Prompt baseline** — a specific committed version of the Patcher prompt against which subsequent prompt iterations are measured. `prompts/patcher.v1.md` becomes the prompt baseline on landing.

- **Prompt win vs model win** — attribution rule for a score delta. When only the prompt changes (same model id + sampling, new prompt hash), the delta is attributed to the prompt. When only the model changes (same prompt hash, new model id or sampling), the delta is attributed to the model. When both change, explicitly decompose the delta by running an intermediate pair that holds one dimension constant.

- **SFT** — supervised fine-tuning. Covered in Phase 3.

- **Preference optimization** — RLHF/DPO-style training on preference signals. Covered in Phase 4.

---

## Candidate base models

Initial open-weight candidates:

- `gpt-oss-120b`
- `Qwen3-Coder-480B-A35B-Instruct`
- `Kimi-K2.6`

Why these:

- `gpt-oss-120b` is OpenAI's most powerful open-weight reasoning model, Apache 2.0 licensed, designed for agentic and tool-using workflows.
- `Qwen3-Coder-480B-A35B-Instruct` is positioned by Qwen as a top open coding model with long context and agentic coding support.
- `Kimi-K2.6` is an open model aimed at long-horizon coding and agentic tasks, with strong published coding benchmark claims.

Initial frontier baselines:

- one Anthropic patcher baseline
- one OpenAI or equivalent frontier baseline

If evaluation cost is high, begin with one frontier baseline only.

---

## Working hypothesis

Open-weight models may not match top frontier models on broad autonomous coding, but they may be trainable to near-parity on `trace`'s narrow role contracts:

- minimal nixpkgs version bumps
- strict output contracts
- maintainer-facing rationale
- upstream-target selection discipline
- refusal to make unrelated edits

The research question is whether the remaining gap is mostly:

- style / contract adherence
- domain format knowledge
- or true reasoning depth

---

## Success criteria

An open-weight `Patcher` is considered viable if, on held-out replay bundles, it achieves:

- fix correctness within 5-10 points of the frontier baseline
- no worse regression rate
- similar or better minimality
- similar or lower reviewer-accept / human-reject divergence
- materially lower cost per merge-ready bundle

These thresholds govern **open-weight viability vs the frontier baseline** and are **additive to, not a replacement for, SPEC §5 ship gates** (≥60% merge-ready, <5% regression, ≥90% reproducer fidelity). An open-weight candidate must clear both the SPEC ship gates AND these viability thresholds to become routeable as a qualified Patcher family.

A model may still be preferred if it is slightly worse on raw patch rate but meaningfully better on:

- cost
- deployability
- auditability
- replayability
- infrastructure control

---

## Training strategy

Use phases. Do not start with full finetuning.

### Phase 1 — Eval-only baseline

- no weight updates
- standard role prompt
- frozen replay corpus only
- compare each open-weight model against the frontier baseline

### Phase 2 — Prompt and tool-protocol tuning

- standardize system prompts
- standardize output schema instructions
- standardize few-shot examples
- no weight updates yet

### Phase 3 — Supervised fine-tuning

Train on historical patch bundles to produce:

- `patch.diff`
- `patch-rationale.md`

The primary goal is better contract adherence, nixpkgs patch style, and upstream-target discipline.

### Phase 4 — Preference optimization

If needed, use reviewer and human preference signals to prefer:

- minimal over broad diffs
- correct **implementation** of the target version supplied by `upstream-ref.json` over misimplementation (target-version **selection** is the UpstreamRefResolver's contract, not the Patcher's; Patcher consumes the resolver's output as given truth per SPEC §1.2)
- strong over weak rationales
- acceptable over misleading patch behavior

Do not begin with autonomy-heavy RL. Too much variance, not enough signal.

---

## Dataset design

Use `trace` artifacts as the dataset substrate.

### Patcher training example

Input (canonical trace artifact names):

- `finding.json` (Scout output; includes `cve_id`, `affected[]` with attr/drv/version, severity, references, mapping)
- `upstream-ref.json` (UpstreamRefResolver output; qualifying target, tier, eligibility verdict)
- `impact.json` (Cartographer output; reverse-closure counts, blast-radius bucket)
- `maintainers.json` (Cartographer output; per-attr maintainer sets)
- the pinned nixpkgs source tree at `finding.json.nixpkgs_rev`, scoped to the `package.nix` (or equivalent) for each entry in `finding.json.affected[]`

Output:

- `patch.diff`
- `patch-rationale.md` (with SPEC §4 mandatory sections: Upstream reference, Why minimal, Alternatives rejected, Downstream risk, Why this version)

### Training-vs-eval data separation

The 51-entry frozen eval corpus at `eval/corpus.json` (frozen 2026-04-23, commit `f4e9bae`) is the held-out bench and is NEVER used as training data. SFT training draws from a **separate** pool of historical nixpkgs CVEs that do not share a `cve_id` with any entry in the frozen corpus. The separation is enforced by the training data-loader: any overlap rejects the training example at load time and is logged. A periodic integrity check runs across the training pool vs `eval/corpus.json` and fails CI on overlap.

### Exclusions

Do not train on:

- advisory-only cases without qualifying upstream fixes
- cases without clear historical resolution
- cases where the "right answer" is disputed
- cases whose bundle artifacts are incomplete or low-confidence

### Splits

- train: older historical CVEs
- dev: separate tuning subset
- test: frozen held-out subset never used for example selection

Also maintain a small Nix-focused hard set covering:

- version bumps
- hash updates
- source URL changes
- multi-output derivations
- language-specific packaging quirks

---

## Evaluation metrics

Use the same project metrics where possible, plus model-specific ones.

Core metrics:

- fix correctness
- minimality
- reproducer compatibility
- regression rate
- merge-ready rate
- reviewer accept / reject
- human review confidence
- cost
- latency

Model-specific metrics (the six Patcher scorers; locked alongside `prompts/patcher.v1.md`):

- **schema-valid output** — unified diff in `patch.diff` parses cleanly AND `patch-rationale.md` has every SPEC §4 mandatory section. Binary pass/fail. (`rationale completeness` and `structured-output failure rate` from earlier drafts fold into this scorer.)
- **exact upstream-ref compliance** — rationale cites the exact `upstream-ref.json` target (tag + commit). Refuses cases where `upstream-ref.json` is absent.
- **hash-verifiability** — every hash-shaped value introduced in `patch.diff` is grounded against `upstream-ref.json.prefetch_hashes[].value` (or, for pre-prefetch bundles, is not on the forbidden-pattern list). Detects silent omission of vendor-style hashes after a version bump. Refusal under rule 8 is treated as a pass. Added 2026-04-27 after the first traefik live run scored 1.0 with a `lib.fakeHash` patch.
- **unrelated-file touch rate** — fraction of files in `patch.diff` that are not under the affected attr's source path. Lower is better; target is 0.
- **minimality** — hunk-count + changed-line-count ratio against the historical fix referenced in the corpus entry's `historical_fix`, capped at 1.0.
- **historical-fix similarity** — unified-diff similarity between `patch.diff` and the corpus entry's `historical_fix.nixpkgs_fix_commit_sha`. Noisy signal useful for trend detection, NOT a hard gate.

Composite **merge-ready rate** is the per-bundle aggregate of the non-advisory scorers that apply (mean over scorers where `applies==True` and `advisory==False`). It measures **contract honour**: did the model produce an outcome that is correct for the inputs it was given? Both "produced a merge-ready patch" and "refused under rule 8 because no grounded evidence was supplied" can score 1.0; both are contract-correct.

Composite **patch_rate** (the SPEC §5 ship-gate metric) is derived from these six plus, later, the Reviewer-side scorers, and measures **patch productivity**: of the dispatchable bundles in scope, how many produced a patch (not a refusal) AND scored ≥0.95 on the per-bundle composite? Definitions:

- **Numerator**: count of (bundle, invocation) pairs where the Patcher produced a `patch` (not `refusal`) AND `composite_merge_ready_rate >= 0.95`.
- **Denominator**: dispatchable bundles in the scope under measurement (advisory-only / `ineligible-*` cases excluded by the `ScoringRefused` dispatch guard, NOT counted in either numerator or denominator).
- **Cohort**: a (model, prompt, corpus-subset) tuple. Different cohorts are not directly comparable; comparing patch_rate across model families requires holding prompt + corpus-subset fixed.

Why both metrics exist: per the 2026-04-27 mbedtls A/B (commits `2d5c12d`, `cd17e09`), the per-bundle composite stays at 1.0 across the prefetch_hashes contract upgrade because both refusal-when-no-evidence and patch-when-evidence-supplied are contract-correct. The composite alone cannot distinguish "Patcher produced 0 of 51 patches" from "Patcher produced 51 of 51 patches" so long as every outcome honoured the contract. patch_rate is the productivity counterpart; without it, "1.0 refusal" and "1.0 patch" could be compared as if they meant the same productivity outcome.

The SPEC §5 ship gate is **patch_rate ≥ 0.60** on the dispatchable subset of the frozen corpus, paired with **composite ≥ 0.95** on every patch counted in the numerator. Refusals under any rule do not count toward the gate; an evaluation cohort that produces only refusals fails ship-gate even if every refusal scored 1.0.

---

## Fine-tune readiness gate

Only proceed from eval-only to SFT if the open-weight model appears "within striking distance" and its failures look trainable.

Good fine-tune targets:

- unnecessary cleanup
- weak rationale
- output formatting failures
- poor target-version choice among nearby acceptable versions
- inconsistent nixpkgs patch style

Bad fine-tune targets:

- repeated failure to identify the correct fix
- inability to reason about the patch at all
- selecting releases that do not actually fix the vulnerability
- persistent misunderstanding of the vulnerability or dependency surface

If the failures are mostly "bad fine-tune targets," stop and choose another base model.

---

## Hugging Face path

Use Hugging Face for:

- dataset versioning
- model hosting
- training jobs or trainer stack
- experiment tracking via dataset/model revisions

Suggested structure:

- dataset repo: `ad-astra/trace-patcher-dataset`
- model repo(s): `ad-astra/trace-patcher-<base>-sft`
- eval artifacts stored with explicit dataset commit + base model revision + trainer config

Version all of:

- base model id and revision
- dataset commit
- prompt version
- trainer config
- eval corpus version

The eval corpus must remain frozen independently of the training split.

---

## Cloudflare role

Cloudflare is a reasonable serving path, not the first place to do training.

Good uses:

- hosted inference for open-weight candidates
- latency and cost experiments
- routing and fallback across model families
- eventual public bundle-viewer integration

Less ideal as the primary training substrate.

Keep the split explicit:

- training and offline eval: controlled research environment
- serving and product experiments: Cloudflare or equivalent

---

## Execution plan

### Phase 0 — already done / in progress

- **freeze the eval corpus** → **done** at commit `f4e9bae` on 2026-04-23. 51 entries, every SPEC §5a composition rule green under `TRACE_REQUIRE_FULL_CORPUS=1`.
- **define exact `Patcher` train/dev/test split** → **blocked on** harvesting a separate SFT pool per Dataset design § Training-vs-eval data separation. The frozen 51 entries are NOT usable as training data.
- **define exact scoring and failure categories** → **in progress**; the six Patcher scorers are locked (see Terminology + Model-specific metrics) and the patch_rate productivity metric is defined alongside per-bundle merge-ready rate. Failure-category taxonomy lands alongside `policy/eval-scorer-result-schema.json`.

Phase 1 prerequisites not yet satisfied (the three actions immediately after this commit):

1. `prompts/patcher.v1.md`
2. Patcher replay runner in `tools/trace_cli/execute.py`, gated by `TRACE_REQUIRE_MODEL=1`
3. The five-scorer runner + `policy/eval-scorer-result-schema.json`

### Phase 1 — baseline benchmark

- benchmark three open-weight models
- benchmark one frontier baseline
- classify failures by category

### Phase 2 — choose one base model

- select the strongest open candidate
- run SFT on the `Patcher` dataset
- re-evaluate on held-out test set

### Phase 3 — preference refinement

- add reviewer and human preference data if SFT helps but does not close the gap

### Phase 4 — routing qualification

- if the open model clears the bar, add it as a qualified `Patcher` family in routing config
- keep a frontier model as challenger / baseline during early deployment

---

## Go / no-go rules

Go forward if:

- held-out improvement is real
- regression does not worsen
- contract adherence improves
- human-review confidence does not drop

Stop if:

- gains appear only on training-like examples
- human reject rate rises
- rationale quality improves but patch correctness does not
- the model overfits nix formatting without improving actual fix quality

---

## Research questions

- Which open-weight base model is strongest for `trace` patching before training?
- How much of the frontier gap is style / contract adherence versus raw reasoning?
- Does SFT on `trace` artifacts improve correctness or mostly formatting?
- Can open-weight patchers reduce cost without increasing human-review burden?
- Are open-weight reviewers viable, or is review still frontier-dominated?

---

## Notes on realism

- The likely first win is a narrow `Patcher`, not a general autonomous coding agent.
- Fine-tuning is most likely to help on style, discipline, and contract adherence.
- Fine-tuning is less likely to close gaps in deep exploit reasoning or difficult reproducer synthesis.
- Success on one role is enough to justify the work; parity across all roles is not required.

