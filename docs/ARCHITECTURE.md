# Architecture

Read [`CONCEPTS.md`](CONCEPTS.md) first for the *what*. This doc is the *where* and *how* — directory layout, control flow, contracts at the module level.

---

## Top-level layout

```
trace/
├── SPEC.md                  v0 design (rev 3, 22 April 2026). The framing doc.
├── README.md                Dev-shell + tests; intentionally thin.
│
├── agents/                  Role implementations, one subdir per role.
├── tools/                   The trace CLI; everything callable from outside the agents.
├── policy/                  Single source of truth: schemas + Rego policy + signing identity.
├── prompts/                 Per-role system prompts (Patcher / Reviewer / Reproducer).
├── docs/                    Specs (per-role contracts), this doc, CONCEPTS.md, DECISIONS.md.
├── tests/                   Pytest tree mirroring agents/ + tools/ subdirs.
├── traces/                  The corpus: example bundles, fixtures, real-CVE bundles.
├── eval/                    Model evaluation harness, corpus, harvesting rules.
├── graph/                   Rust crate: nixpkgs graph snapshots (rebuild closures).
└── .github/workflows/       Builder, Steward, prefetch-smoke, CI.
```

There is no `src/`; trace is Python under `agents/` + `tools/`, plus a Rust graph crate under `graph/`. Nix flake at the root provides the dev shell (`nix develop`).

---

## `agents/` — one role per subdir

Each role subdir is a Python package. Every role's external contract is the file shape it produces; the internal implementation is private.

```
agents/
├── scout/                   CVE feed → finding.json
│   ├── scout.py             Top-level entry: scan(feed_record, graph) → finding
│   └── graph_lookup.py      attr-path resolution against the graph crate's snapshot
│
├── cartographer/            finding.json → impact.json + maintainers.json
│
├── upstream_ref_resolver/   finding.json → upstream-ref.json
│   ├── resolver.py          The deterministic-no-model role.
│   └── prefetch_*.py        nix-prefetch / fetchzip / go-mod-vendor backends.
│
├── patcher/                 finding.json + upstream-ref.json → patch.diff + patch-rationale.md
│   ├── adapter.py           Anthropic / OpenAI / Fake model adapter Protocol.
│   ├── parser.py            Strict-output marker parser; refusals are first-class.
│   └── runner.py            Orchestrates: prompt → model → parse → write.
│
├── reviewer/                patch.diff + patch-rationale → review.md (verdict: accept/reject/defer)
│
├── reproducer/              finding.json + patch.diff → reproducer.nix + log + passthru-tests
│   └── parser.py            Same strict-output structure; signal-substring contract enforced here.
│
├── builder/                 The deterministic runtime.
│   ├── runner.py            Apply patch → patched-build → unpatched.test → patched.test → assemble build.json
│   └── (no model call — Builder is the runner)
│
├── feed_normalizers/        GHSA / vulnpatch-CVE → trace-internal feed shape (Scout's input).
│
└── scorers/                 Reproducer signal-specificity, review-citation, etc. Advisory in v0.
```

Steward has no `agents/steward/` directory — it's a Rego policy (`policy/steward.rego`) plus the dispatch workflow (`.github/workflows/steward.yml`).

---

## `tools/trace_cli/` — the CLI surface

```
tools/trace_cli/
├── cli.py                   `trace` entrypoint. Argparse + role dispatch.
├── execute.py               --execute path: real model calls, replay-writer, provenance-jsonl appender.
├── plan.py                  --plan-only path: dry-run that prints the prompt + resolved inputs.
└── bundle.py                Bundle-assembly helpers (hash, manifest, signed_files mirror).
```

The CLI is the single entry-point humans (and CI) use. Every role can be invoked plan-only or execute, with an optional `--routing-config` to look up the role-to-model pairing.

---

## `policy/` — single source of truth

Schemas (JSON Schema draft 2020-12) for every file in the bundle. Names are predictable: `<file>-schema.json`. The bundle itself is `bundle-schema.json`; per-role outputs have their own. Plus:

```
policy/
├── steward.rego             The 11-rule merge-gate. Single source of truth for what Steward enforces.
├── signing-identity.json    Locked Sigstore keyless OIDC identity (subject_regex + oidc_issuer).
├── routing-config.json      v0-locked role-to-model pairings (Patcher / Reviewer / Reproducer).
└── nixpkgs-fork.json        The fork's identity (URL + canonical default-rev), for verifiers.
```

Schemas are enforced at bundle-creation time (CLI validators) and at gate time (Rego operates on the parsed JSON; it does not re-validate against the schema, but every file Rego reads is schema-shaped at creation time).

---

## `prompts/` — model-facing contracts

```
prompts/
├── patcher.v1.md
├── reviewer.v1.md
└── reproducer.v1.md
```

Each prompt is the model's contract. The `===  BEGIN ... === / === END ... ===` marker structure, the refusal-shape, the strict no-prose rules — all live here. Versions are explicit (v1, v2) because changing a prompt is a behavioural change to a role; the runner records `prompt.sha256` in `replay.json` so a replay knows which prompt produced an output.

There is no Scout / Cartographer / Upstream-ref-resolver prompt because those roles are deterministic-no-model (no LLM call at all in the v0-locked routing).

---

## Control flow: a bundle from feed to signature

```
   ┌───────────┐       ┌──────────────┐       ┌──────────────────────┐
   │ CVE feed  │──────▶│  Scout       │──────▶│  finding.json        │
   │ (NVD/GHSA)│       │  scan()      │       └──────────────────────┘
   └───────────┘       └──────────────┘                 │
                                                         ▼
                       ┌──────────────┐       ┌──────────────────────┐
                       │ Cartographer │──────▶│ impact.json          │
                       │              │       │ maintainers.json     │
                       └──────────────┘       └──────────────────────┘
                                                         │
                                                         ▼
                       ┌─────────────────────┐  ┌─────────────────────┐
                       │ Upstream-ref-       │─▶│ upstream-ref.json   │
                       │ resolver            │  └─────────────────────┘
                       └─────────────────────┘            │
                                                          ▼
                       ┌──────────────┐         ┌─────────────────────┐
                       │ Patcher      │────────▶│ patch.diff          │
                       │ (model)      │         │ patch-rationale.md  │
                       └──────────────┘         └─────────────────────┘
                                                          │
                                       ┌──────────────────┼──────────────────┐
                                       ▼                                     ▼
                       ┌──────────────────────┐        ┌────────────────────────────┐
                       │ Reviewer (model;     │        │ Reproducer (model;         │
                       │ cross-family with    │        │ cross-family with Patcher) │
                       │ Patcher)             │        │                            │
                       └──────────────────────┘        └────────────────────────────┘
                                  │                                ▼
                                  ▼                  ┌────────────────────────────┐
                       ┌─────────────────────┐       │ reproducer.nix             │
                       │ review.md (verdict) │       │ reproducer-log.txt         │
                       └─────────────────────┘       │ passthru-tests.json        │
                                                     └────────────────────────────┘
                                  │                                │
                                  └────────────────┬───────────────┘
                                                   ▼
                       ┌────────────────────────────────────────────────────┐
                       │ Builder (deterministic runtime, no model)          │
                       │ ─ git apply patch.diff to nixpkgs                  │
                       │ ─ nix-build patched derivation                     │
                       │ ─ nix-build reproducer.nix:unpatched.test          │
                       │ ─ nix-build reproducer.nix:patched.test            │
                       │ ─ assert SIGNAL_UNPATCHED + SIGNAL_PATCHED present │
                       │ ─ write build.json + sbom-delta.json               │
                       └────────────────────────────────────────────────────┘
                                                   │
                                                   ▼
                       ┌────────────────────────────────────────────────────┐
                       │ Steward (policy/steward.rego, opa eval)            │
                       │   11 rules; allow ⇔ deny set is empty              │
                       └────────────────────────────────────────────────────┘
                                                   │
                          ┌────────────────────────┴────────────────────────┐
                          ▼                                                 ▼
            ┌─────────────────────────────┐               ┌─────────────────────────────┐
            │ allow=true                  │               │ allow=false                 │
            │  cosign sign-blob over      │               │  signing skipped            │
            │  bundle.canonical.json      │               │  steward-decision.json      │
            │  → Rekor public log entry   │               │  uploaded as artifact       │
            │  → bundle.json signed_      │               │  workflow exits 0 (deny is  │
            │  manifest populated         │               │  data, not infra failure)   │
            └─────────────────────────────┘               └─────────────────────────────┘
```

---

## Workflows (`.github/workflows/`)

```
steward.yml             Gate + sign. Dispatch on a bundle name; runs Builder, Steward,
                        cosign keyless OIDC sign on allow, populates signed_manifest from
                        Rekor lookup. Signing identity locked to this workflow's path.
builder-fork.yml        Real-CVE Builder smoke against the fork (no signing).
builder.yml             Synthetic Builder smoke (no signing).
real-prefetch-smoke.yml Tests the upstream-ref-resolver's prefetch backends.
ci.yml                  Pytest + lint on every PR.
```

`steward.yml` is the only workflow with `id-token: write` permission — it's the only path that produces an OIDC-anchored signature. Verifiers pin against
`subject_regex = ^https://github\.com/Ad-Astra-Computing/trace/\.github/workflows/steward\.yml@refs/(heads/main|tags/v[0-9][^/]*)$`
and refuse any signature claiming a different workflow. Mistakenly enabling `id-token: write` on a different workflow doesn't compromise the identity policy — verifiers pin path + ref pattern explicitly.

---

## Bundle directory layout

```
traces/example/CVE-XXXX-XXXXX--<attr>/
├── bundle.json              Top-level manifest. files{} + signed_manifest{}.
├── finding.json             Scout output.
├── impact.json              Cartographer output (rebuild blast radius).
├── maintainers.json         Cartographer output.
├── upstream-ref.json        Upstream-ref-resolver output.
├── patch.diff               Patcher output.
├── patch-rationale.md       Patcher output.
├── reproducer.nix           Reproducer output (Nix).
├── reproducer-log.txt       Reproducer output (predicted output + signals).
├── passthru-tests.json      Reproducer output.
├── review.md                Reviewer output (verdict + cross-family attestation).
├── build.json               Builder output (CI runtime).
├── sbom-delta.json          Builder output (CI runtime).
├── replay.json              Steward / runner output (canonical replay).
├── provenance.jsonl         Steward / runner output (append-only action log).
├── bundle.sig               cosign sign-blob output (CI runtime).
└── repro/                   Optional: binary PoC files referenced by reproducer.nix.
    └── crash_poc.<ext>
```

Some bundles have role refusals instead of role outputs:

```
├── refusal.json             Patcher refusal (instead of patch.diff).
├── reproducer-refusal.json  Reproducer refusal (instead of reproducer.nix).
└── review-refusal.json      Reviewer refusal (instead of review.md).
```

Each refusal carries a structured `rule:` enum + `reason:` paragraph. Refusals are evidence, not failures; Steward treats them per-rule (e.g. rule-7 denies auto-merge when Builder's `dispatch_outcome=refused-no-reproducer`).

---

## `tests/` mirror

Pytest tree mirrors the agents/ + tools/ structure. Conventional names:

```
tests/
├── builder/
├── cartographer/
├── cli/                     ← tools/trace_cli/ tests
├── eval/                    ← eval-harness tests
├── feed_normalizers/
├── fixtures/                ← real-ci fixtures used by builder.yml/steward.yml
│   └── real-ci/builder/hello/
├── graph/                   ← graph crate enrichment-replay tests
├── integration/             ← cross-role chain tests
├── patcher/
├── reproducer/
├── reviewer/
├── resolver/                ← upstream-ref-resolver tests
├── review/                  ← review-rubric tests
├── schema/                  ← schema-fixture validation
├── scorers/
├── scout/
├── steward/                 ← Rego policy tests via opa eval
└── upstream_ref_resolver/
```

`tests/integration/test_full_chain.py` is the contract: feed entry → all five roles → Builder → Steward, end-to-end, deterministic-no-model attribution. The `real-ci` fixtures under `tests/fixtures/` are the inputs for `builder.yml` and `steward.yml` smokes.

---

## `eval/` — model qualification corpus

Not part of the role chain. The eval harness is how we decide which model goes into `routing-config.json`. See `docs/MODEL_EVAL_PLAN.md` for methodology and `eval/HARVESTING.md` + `eval/INCLUSION_RULES.md` for corpus rules. `corpus.json` + `candidates.jsonl` + `rejection-log.jsonl` are append-only.

---

## `graph/` — Rust crate

Standalone Rust crate that produces nixpkgs graph snapshots (attr-path → drv-path, reverse closures, transitive package deltas) consumed by Cartographer + Scout. Lives in `graph/` because it has its own toolchain (Cargo) and dev shell (`nix develop .#graph`). Not part of the Python role chain at runtime — it produces JSON snapshots that the Python code reads.

---

## What pins what

A short closure of "if you change X you must change Y" relationships:

* **`prompts/<role>.v1.md`** — versioned. Changing the file content without bumping the filename breaks `replay.json:prompt.sha256` matching across runs. New version → new file.
* **`policy/steward.rego`** — referenced by `bundle.json:policy_version` (sha256 of the file). Any change to Rego changes every future bundle's `policy_version` value.
* **`policy/bundle-schema.json`** — referenced by `replay.json:bundle_schema_sha256`. Same property.
* **`policy/routing-config.json`** — referenced by `replay.json:routing_config_sha256`. Locking a new model means new sha → new replay sha.
* **`policy/signing-identity.json`** — read by `steward.yml` at sign time and by every verifier at verify time. The subject_regex is the load-bearing field.
* **`flake.lock`** — referenced by `replay.json:tool_manifest.flake_lock_sha256`. Tool versions are pinned via the flake.

---

## See also

* [`CONCEPTS.md`](CONCEPTS.md) — the *what* (this doc's sibling).
* [`SPEC.md`](../SPEC.md) — v0 framing, kind taxonomy, role boundaries.
* [`BUILDER_V1.md`](BUILDER_V1.md), [`REPRODUCER_V1.md`](REPRODUCER_V1.md), [`STEWARD_V1.md`](STEWARD_V1.md), [`SIGNING_V1.md`](SIGNING_V1.md) — per-role contracts.
* [`DECISIONS.md`](DECISIONS.md) — append-only decision log.
* [`MODEL_EVAL_PLAN.md`](MODEL_EVAL_PLAN.md) — model qualification methodology.
* [`SECURITY_CI_SUPPLY_CHAIN.md`](SECURITY_CI_SUPPLY_CHAIN.md), [`SECURITY_PROMPT_INJECTION.md`](SECURITY_PROMPT_INJECTION.md) — threat models.
