# trace v0 — findings

**Status:** v0 result, 2026-06-09. Synthesizes the corpus built 2026-04 → 2026-06.
**Companion docs:** [`SPEC.md`](SPEC.md) (design), [`CORPUS.md`](CORPUS.md) (per-bundle taxonomy), [`DECISIONS.md`](DECISIONS.md) (running log), [`COST_REPORT_v0.5.0.md`](COST_REPORT_v0.5.0.md) (spend).

---

## The question

> trace tests whether agent systems can turn known upstream security fixes into maintainer-trustworthy nixpkgs evidence bundles faster than current human workflows.

v0 answers a narrower, honest slice of that: **for which CVE classes can a frontier-model agent pipeline produce a cert-green merge-ready bundle — and where does it correctly refuse?**

## The answer (one paragraph)

A Patcher → Reviewer → Reproducer → Builder → Steward pipeline reliably certifies **memory-safety CVEs that have a simple local-file or CLI trigger and crash observably on the as-shipped binary** — directly for the always-crashing classes (CWE-476 null-deref, CWE-121 stack-canary), or via ASAN instrumentation for the silent classes (CWE-125 OOB-read, CWE-416 UAF, CWE-191 underflow) when the trigger is cheap to construct. Both `version-bump` and `overlay`/`fetchpatch` patch shapes work. The pipeline **cannot** certify CVEs that require protocol-internal fixture engineering (ASN.1 schemas, concurrency races, opaque container formats), validation-bypass discovery, network/daemon setup, or whose crash is optimization-masked beyond cheap ASAN recovery. Crucially, on every un-certifiable candidate the framework **refused to mint a false signal** rather than faking a green result — that honest-refusal behavior is itself the load-bearing finding about the trust layer.

## The numbers

| | count | |
|---|--:|---|
| Real-CVE bundles bootstrapped | 16 | |
| **Cert-green** (merge-ready, Linux build.json, both SIGNALs verified) | **8** | matio, git-lfs, assimp, libxmp, libtiff ×2, micropython, proxychains-ng |
| **Retired** (filter passed, chain refused honestly) | **8** | wget2, libtasn1, django, uriparser, libpng, lrzip, quickjs-ng, mupdf |
| Retention rate | ~50% | |

Cost (v0.5.0 baseline, N=3 sandbox-positive cohort): **~$0.39 mean per merge-ready bundle**; Patcher (opus) is 68% of spend. Sunk cost on the 9 bootstrap-retired candidates: ~$3.47 total (~$0.39/bundle). See [`COST_REPORT_v0.5.0.md`](COST_REPORT_v0.5.0.md).

> The ~50% retention rate is not a defect — it is the result. The retirements map the boundary of what agents can certify, and the framework's refusal to fake them is the evidence that the trust layer holds.

## What certifies (the green corpus)

| bundle | CVE class | what made it certifiable |
|---|---|---|
| `git-lfs` CVE-2025-26625 | CWE-59 symlink arbitrary file-write | local-FS PoC: place a symlink at an LFS-tracked path, run `git lfs checkout`. First sandbox-positive green. |
| `assimp` CVE-2025-2751 | CWE-125 NULL-ptr deref | crashes directly (address 0 always unmapped); major-version-jump 5.4.3→6.0.2. |
| `matio` CVE-2025-2337 | stack-buffer-overflow in `strdup_vprintf` | ASAN rc=42 on a 1000-double fixture; version-bump. |
| `libxmp` CVE-2025-47256 | CWE-191 underflow → CWE-121 underwrite | ASAN catches the write GCC-14 folded into mapped stack memory; version-bump. |
| `libtiff` CVE-2025-8176 | CWE-416/122 heap overflow, off-by-one in `quant_fsdither` | F21-class: silent at -O2, ASAN rc=42; clean 4.7.0→4.7.1. |
| `libtiff` CVE-2024-13978 | (Linux Builder infra anchor) | deterministic hand-authored sandbox-positive template. |
| `micropython` CVE-2026-1998 | CWE-119/843 type confusion in `mp_import_all` | SIGSEGV directly; first cert-green **overlay (fetchpatch)** patch shape. |
| `proxychains-ng` CVE-2025-34451 | CWE-121 stack overflow in `proxy_from_string` | F21b: silent at -O2, ASAN rc=42. |

## What does not certify (the retirement taxonomy)

This is the empirical map. Each class is codified as a filter criterion in [`CORPUS.md`](CORPUS.md#sandbox-positive-poc-suitability-filter-post-2026-05-17-f6); each was learned through an honest failure, not designed up front.

| class | bar | example | why agents can't certify it |
|---|---|---|---|
| **F6** network/daemon | PoC needs network egress or a listener | wget2 CVE-2025-69194 (metalink HTTP) | the Nix build sandbox is network-isolated by contract. |
| **F8** construction depth | PoC needs protocol-internal fixture engineering | libtasn1 CVE-2025-13151 (ASN.1 schema → 1-byte off-by-one); mupdf CVE-2026-3308 | a sonnet-class model can't build the schema/box-layout that walks the parser to the bug from a CVE summary + diff. |
| **F8b** concurrency | crash is a race needing timing control | lrzip CVE-2025-15571 (UAF at 0x80 in `ucompthread`) | race window is sub-ms without instrumented `sleep()` delays; fixture also needs protocol-correct stream headers. |
| **F10** validation-bypass | fix *strengthens* an existing check | django CVE-2025-59681 (MySQL alias quoting) | naive malicious input is already rejected by the older check; discovering the narrow bypass needs reading the fix diff. |
| **F11** shipped-binary masking | bug is optimization-elided in the as-shipped artifact | uriparser CVE-2025-67899 (TCO elides recursion); quickjs-ng CVE-2026-1144 (UAF write in glibc free-list); libpng CVE-2025-66293 (silent OOB read) | crashes at -O0 but not at nixpkgs -O2; recoverable only with ASAN, and only when the trigger is cheap (it wasn't, here, on top of build-timeout limits). |

The crisp rule the corpus produced: **memory-safety CVEs reliably crash at default optimization only for CWE-476 and CWE-121; everything else (CWE-125/416/674/190) is silent without ASAN.** The certifiable set is "(always-crashing) OR (silent-but-ASAN-instrumentable AND cheap-to-trigger)."

## What v0 does NOT claim

- **Not** that agents can certify arbitrary CVEs. The certifiable class is specific and ~half of harvested candidates fall outside it.
- **Not** a human-review-panel result. SPEC §7's ≥3-reviewer panel pilot has not run; "maintainer-trustworthy" is asserted by the contract layer (signing, refusal rules, Steward), not yet by external reviewers.
- **Not** a throughput-vs-humans benchmark. We have per-bundle cost (~$0.39) but no head-to-head against a human nixpkgs maintainer's time on the same CVEs.
- **Not** a fine-tuning result. The corpus (N=8 green) is far below the ~50 needed to train an open-weight replacement for the frontier Patcher; that remains future work.

## What the result is good for

1. **A defensible v0 thesis answer**: agents *can* turn a well-defined class of known fixes into cert-green evidence bundles, and the trust layer *correctly refuses* the rest. A well-documented boundary is a publishable result by SPEC's own bar.
2. **A reusable harvest filter**: the F6–F11 taxonomy lets future harvests pre-screen candidates instead of burning ~$0.39 + several CI cert-cycles discovering the boundary per bundle.
3. **A trust-layer demonstration**: every retirement is a case where the framework declined to fabricate a signal. That is the property a maintainer actually needs to trust the auto-merge route.

## Open arcs (deferred, not blocking the v0 result)

- Human review-panel pilot (SPEC §7 q5) — the missing leg of "maintainer-trustworthy."
- `trace pr` → real fork PR end-to-end (subcommand shipped 2026-06-08; not yet exercised against a live fork).
- Fine-tuning feasibility probe (Qwen2.5-Coder) — needs more corpus or a smaller-N feasibility design.
- Throughput-vs-human benchmark.
