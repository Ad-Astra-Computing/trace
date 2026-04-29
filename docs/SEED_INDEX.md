# Seed Index

The eight real-CVE bundles under `traces/example/CVE-*/` each demonstrate a distinct shape in the v0 contract. This document is the single-page external-review map: what each bundle is for, what it proves, what it does *not* prove, and where to look first if you're auditing the corpus.

The synthetic `CVE-0000-*` fixtures are not catalogued here; they exist to exercise specific Steward rules and per-document schema edges, and are read against `expect.json` notes individually.

## At a glance

| bundle | kind | provenance family | what it demonstrates |
|---|---|---|---|
| [`CVE-2024-13978--libtiff`](../traces/example/CVE-2024-13978--libtiff/) | auto-merge | deterministic-no-model | seed for the auto-merge contract end-to-end, no model spend; sandbox-positive reproducer |
| [`CVE-2024-49195--mbedtls`](../traces/example/CVE-2024-49195--mbedtls/) | auto-merge | model-attested (Patcher) | clean single-hash patch-release; rule-8 hash-verifiability scorer's cleanest test case |
| [`CVE-2025-13878--bind`](../traces/example/CVE-2025-13878--bind/) | auto-merge | model-attested (Patcher + Reproducer) | small-delta patch on a large `package.nix`; honest rule-7 deny when no reproducer is feasible |
| [`CVE-2025-4598--systemd`](../traces/example/CVE-2025-4598--systemd/) | human-review-required | model-attested (Patcher + Reviewer) | `blast-radius-exceeds-threshold` route on a foundational package |
| [`CVE-2025-67899--uriparser`](../traces/example/CVE-2025-67899--uriparser/) | human-review-required | model-attested (Patcher + Reproducer) | `major-version-jump-requires-review` route + reproducer-refusal under rule 3 |
| [`CVE-2025-7207--mruby`](../traces/example/CVE-2025-7207--mruby/) | human-review-required | deterministic-no-model | `cross-family-pair-unavailable` route; PoC-public-but-sandbox-silent class |
| [`CVE-2025-9230--openssl_3`](../traces/example/CVE-2025-9230--openssl_3/) | human-review-required | model-attested (Patcher) | `blast-radius-exceeds-threshold` on a transitive dependency of almost the entire tree |
| [`CVE-2026-25949--traefik`](../traces/example/CVE-2026-25949--traefik/) | auto-merge | model-attested (Patcher + Reviewer) | first live Patcher run; Go vendorHash discipline; maintainer-driven scope widening that the Patcher must *not* replicate |

## Per-bundle detail

### `CVE-2024-13978--libtiff` · auto-merge · deterministic-no-model

libtiff `fax2ps` null-pointer dereference under `TIFFTAG_FAXFILLFUNC`. The bundle ships the upstream-attached crash TIFF (`repro/crash_poc.tif`, 9556 bytes, gitlab issue #649) and a reproducer that synthesises an unpatched libtiff via `overrideAttrs (old: { patches = filter (p: !match "CVE-2024-13978.*" p.name) old.patches; })` and runs `fax2ps` against the PoC. The discriminating signal is SIGSEGV on unpatched, exit-1 on patched.

* **What's load-bearing**: `patch.diff` is byte-equivalent to the nixpkgs backport at `372f8113f50783002c77f1490aae98ce888608d2` (PR [#436742](https://github.com/NixOS/nixpkgs/pull/436742)). Two upstream fix commits, both libtiff-master, both upstream-signed. The PoC is the same artifact upstream attached to its own bug tracker.
* **What's pre-baked**: `patch-rationale.md`, `review.md`, `reproducer-log.txt`, `build.json`, the scoring reports. None of those came out of a model invocation; each carries an explicit "not produced by a model invocation" provenance preface. CI Builder overwrites `build.json` at dispatch time.
* **Notable property**: this bundle is the v0 Hydra-graduation criterion *concrete*. Run [25077946199](https://github.com/Ad-Astra-Computing/trace/actions/runs/25077946199) timed out on `patched_build`, producing a clean rule-8 deny with skip-sign. The architecture worked: no false signature, no time-budget-bypass shortcuts, the deny is the milestone. See [DECISIONS.md](DECISIONS.md) entry "libtiff CVE-2024-13978 dispatch".

### `CVE-2024-49195--mbedtls` · auto-merge · model-attested

mbedtls patch-release case. The historical nixpkgs fix at `bd4bd87293ad` is exactly 2+2 lines: version bump and matching `src.hash`. No `vendorHash`, no `cargoHash`, no `npmDepsHash`.

* **Pedagogical role**: cleanest test case for the hash-verifiability scorer (rule-8 generalization). Only one hash slot to verify, no transitive package changes, no maintainer-driven ride-along scope. Either the Patcher refuses with "rule 8: no grounded hash for this slot," or it emits the prefetched hash byte-equal to the upstream-derived value. There is nowhere for a hallucinated hash to hide.

### `CVE-2025-13878--bind` · auto-merge · model-attested

ISC bind 9.20.17 → 9.20.18 patch-release on a 178-line `package.nix`. The historical nixpkgs fix (`6bd98c02c5f7`) is again exactly 2+2 lines: version + `src.hash`. Empty intersection with maintainer-driven changes.

* **Pedagogical role**: tests Patcher's discipline on a large existing package definition. The CVE-driven minimum diff is 2+2 lines; Patcher must not generate a "while we're here" cleanup pass. Reproducer correctly refuses (network DNS daemon → no sandbox-positive reproducer feasible), Steward correctly denies on rule-7 with skip-sign. See run [25074542863](https://github.com/Ad-Astra-Computing/trace/actions/runs/25074542863).
* **Notable property**: pairs with the libtiff bundle as a "deny-honestly" demonstration on the auto-merge path: bind for "no reproducer can be built for this CVE class," libtiff for "Builder cannot fit this bundle in 30 minutes." Two distinct deny shapes, both reach skip-sign cleanly.

### `CVE-2025-4598--systemd` · human-review-required · model-attested

systemd-coredump signal-handler race (CWE-364, CVSS 4.7). Patch is canonical clean patch-release: version bump 257.5 → 257.6 with `src.hash` update. No `vendorHash` (systemd is not Go), no transitive package changes.

* **Pedagogical role**: `human-review-required` route via `kind_reason = blast-radius-exceeds-threshold`. systemd is foundational; reverse-closure count exceeds the v0-default threshold of 500 by a wide margin. Even when the patch itself is clean, operational risk on a bottom-of-the-stack package crosses the human-review line. The bundle proves the threshold gate fires on real, low-CVSS, structurally-clean changes when *operational* risk dominates.

### `CVE-2025-67899--uriparser` · human-review-required · model-attested

uriparser 0.9.9 → 1.0.0 (project's first stable major release). Unbounded-recursion / stack-consumption (CWE-674) via `ParseMustBeSegmentNzNc` with comma-heavy input.

* **Pedagogical role**: `major-version-jump-requires-review` route + a reproducer-refusal under rule 3 with the principled reason "triggering unbounded recursion in the build sandbox will exhaust the sandbox's stack limit and crash the build process itself."
* **Pipeline-bug provenance**: the first run for this bundle (preserved under [`_first-run-archive/`](../traces/example/CVE-2025-67899--uriparser/_first-run-archive)) surfaced a contract bug in v0 Patcher: `github-release-archive` confidence + `nix-prefetch-url` against `fetchFromGitHub` produces a hash divergent from what `fetchFromGitHub` actually demands. The current bundle is the post-pipeline-fix re-run, with a patch byte-identical to the historical nixpkgs fix at `e9da914af2cd`. That archive is intentional; deleting it would erase the evidence that the pipeline was wrong before it was right.
* **Notable property**: this is the first signed real-CVE bundle in the v0 ledger. Run [25075869027](https://github.com/Ad-Astra-Computing/trace/actions/runs/25075869027), `rekor_log_index = 1397922891`. Verifiable by anyone with `cosign verify-blob` against the locked workflow identity.

### `CVE-2025-7207--mruby` · human-review-required · deterministic-no-model

mruby `scope_new` heap-buffer-overflow at `mrbgems/mruby-compiler/core/codegen.c`. `nregs` is not initialized; `stack_clear` (`src/vm.c:101`) writes past the allocated stack region. Triggered by an 18-byte Ruby program (`module K retry end`) loaded via `mrb_load_string`.

* **Pedagogical role**: `cross-family-pair-unavailable` route. Deterministic-no-model means no model pair, so by definition no cross-family pair to enforce. Pairs with libtiff to populate the deterministic-no-model family across both bundle kinds: libtiff (auto-merge with sandbox-positive reproducer) and mruby (human-review-required with reproducer-refusal).
* **Why no reproducer**: heap-buffer-overflow at `scope_new` is silent on a non-ASAN build. `reproducer-refusal.json` declares rule 3 with the principled reason; the 18-byte PoC ships at `repro/mruby_crash.txt` for a v1 Reproducer that runs against an ASAN-aware Builder profile. PoC is real (OSV CVE-2025-7207 references[] type=EVIDENCE).
* **Upstream provenance**: fix commit `1fdd96104180...` is GPG-signed by Yukihiro "Matz" Matsumoto personally (verified via GitHub API `verification.verified = true`). nixpkgs precedent at `4d9e5f64b7a7` (PR [#450791](https://github.com/NixOS/nixpkgs/pull/450791), 2025-10-10).

### `CVE-2025-9230--openssl_3` · human-review-required · model-attested

openssl_3 3.0.17 → 3.0.18 CMS RFC 3211 KEK-unwrap OOB read/write (CVSS 7.5 HIGH). Resolver verdict: eligible at patch-release tier. Patch content byte-identical to the historical nixpkgs fix at `9e4cf668a33a`.

* **Pedagogical role**: `blast-radius-exceeds-threshold` route on the most extreme transitive-dependency case in the corpus. openssl is a dep of almost everything; reverse-closure count is `>5000`. The bundle proves the threshold gate handles the upper bucket cleanly, with a structurally-clean patch and a high-CVSS finding.

### `CVE-2026-25949--traefik` · auto-merge · model-attested

traefik 3.6.7 → 3.6.8 STARTTLS denial-of-service. Minimum CVE-driven fix: version bump + `src.hash` + `vendorHash` updates.

* **Pedagogical role**: the first live Patcher run in the corpus. Tests Go-package vendorHash discipline (the Patcher must produce a real `vendorHash`, not a hallucinated one) and the "no maintainer-driven ride-along" rule. The historical nixpkgs fix at `be6f65471a8d` *also* bumps `buildGo124Module` → `buildGo125Module`; that is a maintainer scope-widening, not CVE-driven, and the Patcher must not replicate it. The bundle's expected behaviour is for Patcher to emit the narrower CVE-only diff.

## Cross-cutting observations

* **Three distinct human-review-required sub-shapes** are exercised: `major-version-jump-requires-review` (uriparser), `blast-radius-exceeds-threshold` (systemd, openssl_3), `cross-family-pair-unavailable` (mruby). Steward's allow-path on `human-review-required` is gated only on rules 4 + 5; the diversity across `kind_reason` values exercises the *upstream* of that gate (Cartographer / UpstreamRefResolver eligibility) more thoroughly than a same-shape repetition would.
* **Two distinct auto-merge deny shapes** are exercised cleanly: rule-7 deny when no reproducer is feasible (bind), rule-8 deny when Builder cannot fit a bundle in its time budget (libtiff). Both reach skip-sign with no false-positive signature.
* **Provenance-family coverage** spans deterministic-no-model (libtiff, mruby) and model-attested (the rest). Every model-attested bundle's Patcher is `claude-opus-4-7`; cross-family pairs are landed where Reviewer / Reproducer participate, satisfying the cross-family rule mechanically.
* **One signed real-CVE bundle** exists today: uriparser, run 25075869027, rekor_log_index 1397922891. The auto-merge real-CVE-signed milestone remains gated on (a) sandbox-positive reproducer corpus extension AND (b) v1 Hydra / large-runner / pre-warmed-cache infrastructure to clear Builder's saturation point.

## How to verify any claim in this index

Each bundle's `README.md` and `expect.json:notes` carry the public-source citation table for every load-bearing claim. The signed bundles' Rekor log indices in [`DECISIONS.md`](DECISIONS.md) (search for "v0 ledger" + "Signing row") are checkable via `cosign verify-blob` against the locked workflow identity in [`policy/signing-identity.json`](../policy/signing-identity.json). If anything in this index is found to be inaccurate, the bundle is wrong; open an issue.
