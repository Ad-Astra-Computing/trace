# trace

**Status**: v0 spec rev 3, 22 April 2026
**Org**: Ad Astra Computing

**v0 thesis (narrow, measurable):**
> trace tests whether agent systems can turn known upstream security fixes into maintainer-trustworthy nixpkgs evidence bundles faster than current human workflows.

**Long-term vision (post-v0):** specialized agents own subgraphs of the nixpkgs derivation tree and produce merge-ready evidence bundles for CVE remediation, version currency, and (eventually) novel-vuln findings. v0 proves the bundle loop works on the easiest honest slice. Everything else is earned.

**Framing honesty:** trace v0 is an **upstream-fix integrator for nixpkgs**, not a vulnerability-repair system. Agent-original patches are out of scope until the integrator path is measurably reliable.

Runs in isolation as an Ad Astra research artifact. Not upstreamed directly to nixpkgs. Bundles may be offered upstream per-patch with full provenance.

---

## 0. Design principles (non-negotiable)

These principles outrank any section below. If a later decision conflicts, the principle wins.

1. **Moat is data and policy, not models.** Graph data, eval corpus, bundle schema, deterministic Steward policy, reproducible build evidence. Model capability will commoditize; do not bet the project on a named model.
2. **Models are replaceable.** Every agent role is a **contract** (input schema, allowed tools, network policy, output schema, validation checks, eval-score threshold). Any model meeting the contract and clearing the eval bar can fill the role. Capability routing, not fixed assignments.
3. **Stronger models reduce toil; they never lower gates.** Runnable proof, upstream refs, rebuild evidence, adversarial review. Better models mean higher expectations, not looser ones.
4. **Replayability is mandatory.** Every bundle is replayable with the same nixpkgs rev, prompt hash, model/provider metadata, tool versions, and policy version. Model upgrades are evaluated empirically against replayed runs.
5. **Avoid model monoculture.** Different model *families* for Patcher and Reviewer where possible. Periodic challenger-model evals. Regression dashboards per model × prompt version. Quarantine any model that raises patch rate while raising false-confidence.
6. **Three lanes are distinct: finding, fixing, proving.** v0 ships only the fixing + proving lane, scoped to known CVE with known upstream fix. Finding (novel vuln discovery) is a separate future lane with separate guardrails, because frontier-model capability there is exactly the dual-use surface we do not want to casually wade into.

---

## 1. Core concepts

### 1.1 The trace graph
The full nixpkgs derivation graph, materialized as a queryable artifact (SQLite + Parquet snapshots per revision). Every node is a derivation; every edge is a `buildInputs` / `propagatedBuildInputs` / `nativeBuildInputs` relation. Each node carries:

- `drv_path`, `attr_path`, `pname`, `version`, `src.url`, `src.hash`
- `cpe` / `purl` identifiers (best-effort mapped)
- known CVEs (from NVD, GHSA, OSV feeds)
- downstream rebuild count (reverse closure size)
- last-touched commit + maintainer set

The graph is the **substrate**. Everything else operates on it.

### 1.2 Role contracts (capability routing, not fixed models)
Agents are assigned **roles**, not packages, and roles are **contracts**, not model assignments. Each role declares:

```yaml
role: patcher
input_schema: schemas/patcher-input.json
output_schema: schemas/patcher-output.json
allowed_tools: [read_tree, read_cve, read_upstream_ref]
network: none
validators: [diff-minimality, upstream-ref-present, no-version-bump-beyond-cve]
eval_threshold:
  fix_correctness: 0.75
  regression_rate_max: 0.05
  reproducer_fidelity_min: 0.90
```

Any model (open or closed, any vendor) that meets the contract and clears the eval bar on the replay corpus can be routed to the role. A routing config selects per-run which qualified model runs the role; the Patcher/Reviewer pair is required to come from different model families when a qualified cross-family pair exists.

A single package is touched by multiple role-agents during a patch cycle:

| Role | Owns | Output |
|---|---|---|
| **Scout** | Feed ingestion (NVD, GHSA, OSV, upstream release RSS) | `finding` records against drv_paths |
| **Cartographer** | Graph maintenance, reverse-closure queries | `impact` reports (what rebuilds if X changes) |
| **UpstreamRefResolver** | Resolving the qualifying upstream fix reference (§2a) and deciding v0 eligibility | `upstream-ref.json` with release/tag URL, changelog/advisory links, current & target versions, patch/point/major classification, eligibility verdict |
| **Patcher** | Producing the minimal diff **against an already-qualified target** | candidate patch + rationale |
| **Reproducer** | Confirming the vuln *and* the fix with a runnable PoC in a sandboxed derivation | `reproducer.nix` + before/after trace |
| **Builder** | Driving Hydra-style rebuild of the impacted closure | build log, cache hit rate, failure triage |
| **Reviewer** | Adversarial read of the patch: does it fix the CVE? does it introduce regression? does it match upstream? | `review.md` with verdict |
| **Steward** | Final merge gate; only accepts bundles that pass all prior roles | signed merge commit |

Scout, Cartographer, UpstreamRefResolver, Builder are deterministic tooling (LLM calls allowed only as helpers for release-notes / advisory parsing, and their outputs are validated against hard schemas). Patcher, Reproducer, Reviewer are where model quality matters most and where capability routing pays off. Steward is pure policy.

**Separation of concerns:** Patcher does not decide whether it is allowed to act. UpstreamRefResolver produces the qualifying target (or an ineligibility verdict) before Patcher is invoked. An ineligible finding is routed to the advisory-only path; Patcher never sees it.

### 1.3 The evidence bundle (the "trace")
One CVE → one bundle. A bundle is a directory under `traces/<year>/<cve-id>/` containing:

```
traces/2026/CVE-2026-12345/
├── finding.json         # Scout: CVE, CPE match + confidence, affected drv_paths, severity
├── impact.json          # Cartographer: reverse closure, rebuild count, critical downstream
├── maintainers.json     # Cartographer: current nixpkgs maintainer set for affected attrs
├── upstream-ref.json    # UpstreamRefResolver: release/tag URL, changelog, versions, eligibility
├── patch.diff           # Patcher: minimal diff against qualified target in upstream-ref.json
├── patch-rationale.md   # Patcher: why this diff, upstream refs, why-this-version, alternatives
├── passthru-tests.json  # Reproducer: passthru.tests results before and after
├── reproducer.nix       # Reproducer: derivation demonstrating vuln on unpatched, passes on patched
├── reproducer-log.txt   # Reproducer: captured before/after output
├── build.json           # Builder: closure build result, cache stats, failures, blast radius
├── review.md            # Reviewer: verdict + adversarial notes (different model family from Patcher)
├── sbom-delta.json      # SBOM before/after (CycloneDX)
├── replay.json          # Full replay manifest (§9): revs, prompt hashes, model IDs, tool versions
├── provenance.jsonl     # Append-only log: every agent action, model, prompt hash, output hash
└── bundle.sig           # Steward signature over the above (sigstore / Ad Astra key)
```

A human maintainer sees the bundle and can **decide accept or reject without opening a browser tab or rebuilding locally**. That "self-contained decision" property is the north-star metric, measured as decision-time and decision-confidence on a human review panel. "60 seconds" is a rule of thumb, not the gate.

Bundles should mirror what nixpkgs maintainers actually care about, not just what's CVE-shaped: update rationale, passthru tests, rebuild blast radius, Hydra (or Builder) result, maintainer ownership, and a one-line "why this version, not another." These fields are enforced by `policy/bundle-schema.json` (built first in §6.0) and checked deterministically by Steward.

---

## 2. Security posture — patches must be correct *and* safe

Agent-authored patches are a supply-chain attack surface. Non-negotiables:

1. **No network during Patcher or Reviewer runs.** Patch generation happens in a sandbox with only the pinned source tree and CVE metadata as input. Network is allowed only in Scout (feeds) and Builder (substituter).
2. **Two forms of proof, both required for v0 auto-merge.** (a) `passthru-tests.json` — existing nixpkgs `passthru.tests` must pass on the patched tree (regression confidence: "we didn't break the package"). (b) `reproducer.nix` — a vuln-specific derivation that fails on unpatched and passes on patched (vulnerability confidence: "we actually fixed *this* CVE"). Existing `passthru.tests` alone are not a reproducer — they demonstrate package health, not vulnerability presence. If a vuln-specific reproducer cannot be generated, the bundle ships as advisory-only, never auto-merged.
3. **Upstream cross-check.** Patcher must cite an upstream release or tag that contains the fix (see §2a for what counts). Bundles without a qualifying upstream reference are **advisory-only in v0** — emitted as findings, never advanced to Patcher. Quarantine review flow is deferred to post-v0.
4. **Two-role rule, cross-family.** Patcher and Reviewer run as separate agents and MUST come from different model families once two qualified families clear the eval bar. Same-family pairs are permitted only when no qualified cross-family pair exists, and are flagged in `replay.json`. Same-model self-review is banned outright.
5. **Provenance is append-only.** Every prompt, every model ID, every tool call, every output hash lands in `provenance.jsonl`. Bundles with gaps are rejected.
6. **Steward is a policy engine, not a model.** Deterministic checks: signatures present, reproducer exits correctly, build succeeded, review verdict == accept, provenance complete. No LLM in the merge gate.
7. **Signed commits end-to-end.** sigstore + Ad Astra signing identity. Revocable.
8. **CPE/PURL mapping is explicitly risky.** nixpkgs → CPE mapping will produce false matches and missed matches. Scout emits a **confidence score** on every finding and writes mapping failures to a reviewable queue. Low-confidence findings never auto-advance to Patcher.
9. **Finding vs fixing vs proving are separate lanes.** v0 ships fixing + proving. Finding (novel-vuln discovery) is deferred with separate guardrails; frontier-model cyber-capability trajectory (see reports on restricted access to Claude Mythos Preview) is exactly why we do not casually enable it.

---

## 2a. What counts as a qualifying "upstream fix" (v0)

In nixpkgs terms, the v0 patch primitive is almost always a **version bump**, not a source patch applied on top of the current version. "Upstream fix" means one of:

1. **Security patch release** (preferred): a release whose sole or primary purpose is the CVE fix (e.g. `1.4.7` → `1.4.8` where release notes call out the advisory). Auto-eligible.
2. **Tag or point release that contains the fix among small, related changes**: permitted when the changelog between current and target is small and security-relevant. Patcher rationale must enumerate the delta.
3. **Major version jump**: **not permitted** unless upstream explicitly refuses to backport and the fix exists only in the new major. Requires the rationale to quote the upstream decision and is flagged for mandatory human review (not auto-merge even on green Steward).

Hard rules:
- Rationale MUST include current version, target version, and a one-line "why this version, not an earlier point release that also contains the fix."
- `sbom-delta.json` MUST be computed between current and target; if the delta crosses a configured "large dependency movement" threshold (e.g. >10 transitive package changes, or any new direct dep), bundle is flagged for human review.
- Cherry-pick / manual backport patches are explicitly out of scope for v0 (see §6 gate 3).

---

## 3. Architecture

### 3.1 Repo layout (monorepo)
```
trace/
├── SPEC.md                     # this file
├── flake.nix                   # pinned toolchain, all commands run via `nix develop`
├── graph/                      # trace-graph builder (Rust)
│   ├── src/
│   └── snapshots/              # parquet + sqlite per-rev
├── agents/
│   ├── scout/
│   ├── cartographer/
│   ├── upstream-ref-resolver/
│   ├── patcher/
│   ├── reproducer/
│   ├── builder/
│   ├── reviewer/
│   └── steward/
├── prompts/                    # versioned, hash-pinned prompts per role
│   ├── patcher.v1.md
│   ├── reviewer.v1.md
│   └── ...
├── policy/
│   ├── steward.rego            # OPA policy for merge gate
│   └── bundle-schema.json
├── traces/                     # evidence bundles (the output)
├── nixpkgs/                    # git submodule, pinned fork
├── .github/workflows/
│   ├── scout.yml               # hourly feed poll
│   ├── patch-cycle.yml         # on finding → run full pipeline
│   └── steward.yml             # on bundle complete → merge gate
└── eval/                       # offline eval harness with known-historical CVEs
```

### 3.2 Runtime
- **v0**: GitHub Actions for orchestration, self-hosted runner with nix + binary cache for builds. Acceptable for a single-digit-PR-per-day cadence.
- **v1 (when Builder saturates Actions)**: migrate Builder to a Hydra instance on Ad Astra infra; keep orchestration in Actions.
- **Agents run as CLI processes** inside job containers. No long-running agent service in v0.

### 3.3 Data flow (one CVE, end-to-end)
1. Scout job (cron, hourly) ingests NVD/GHSA deltas, emits `finding.json` with CPE/PURL confidence to a PR branch `trace/<cve-id>`. Low-confidence findings go to the mapping-failures queue.
2. Cartographer GHA consumes the finding, queries the graph snapshot, appends `impact.json` and `maintainers.json`.
3. UpstreamRefResolver GHA produces `upstream-ref.json`: qualifying release/tag URL, changelog & advisory links, current version, target version, patch/point/major classification, eligibility verdict. If verdict is ineligible, the bundle diverts to the advisory-only path and the pipeline ends here.
4. Patcher GHA runs in sandbox against the qualified target, produces `patch.diff` + `patch-rationale.md`. Patcher treats `upstream-ref.json` as given truth; it does not re-litigate eligibility.
5. Reproducer GHA produces + runs vuln-specific `reproducer.nix` on unpatched and patched trees, and captures `passthru-tests.json` on both. Attaches logs.
6. Builder GHA rebuilds the impacted closure (bounded by impact.json's rebuild count; over threshold → human review required).
7. Reviewer GHA (different model family from Patcher where qualified pair exists) produces `review.md`. Verdict ∈ {accept, reject, escalate}.
8. Steward GHA runs OPA policy against `policy/bundle-schema.json` and `policy/steward.rego`. If all green, signs bundle and opens the merge PR. If red, posts the bundle to a human queue.
9. Human maintainer sees a merge-ready PR with the bundle inline. One-click merge or reject (decision captured per §5b rubric).

---

## 4. The Patcher and Reviewer prompts (quality matters most here)

Prompts are versioned files under `prompts/`. Every bundle records the prompt hash it ran against. Changes to prompts require an eval-suite pass.

**Patcher prompt skeleton** (`prompts/patcher.v1.md`):
- Inputs: CVE record, affected `drv_path`, current source tree, `upstream-ref.json` (a qualifying upstream fix reference is mandatory in v0; absence means Patcher is not invoked), impact.json.
- Constraints: minimal diff, cite upstream, no refactors, no style changes, no version bumps beyond what the CVE requires, do not touch unrelated attributes.
- Output contract: unified diff + rationale markdown with mandatory sections (Upstream reference, Why minimal, Alternatives rejected, Downstream risk).
- Failure modes to avoid (explicit in prompt): speculative patches with no upstream ref, "helpful" cleanups, version bumps that pull in new CVEs, patches that paper over the symptom rather than fix the root cause.

**Reviewer prompt skeleton** (`prompts/reviewer.v1.md`):
- Inputs: the full bundle so far (finding, impact, patch, rationale, reproducer log).
- Adversarial stance required: assume the Patcher is wrong; find the reason.
- Must produce: verdict, list of concrete concerns with file:line refs, whether the reproducer actually exercises the vulnerability (not a proxy), whether the patch diverges from upstream.
- Cannot be the same model that produced the patch.

Prompts eventually ship with ~10 golden examples drawn from the eval corpus. Per §6.0, prompt authorship comes *after* schema, policy, corpus, replay harness, rubric tooling, and the deterministic data layer exist — golden examples are selected empirically from the frozen corpus, not hand-picked in advance.

---

## 5. Eval harness

Before any prompt or model change ships, it runs against a corpus of historical CVEs with known-good fixes (harvested from nixpkgs git history + NVD). Metrics:

- **Fix correctness**: does the agent-produced patch match the historical fix semantically? (diff-similarity + Reviewer verdict)
- **Reproducer fidelity**: does the reproducer actually trigger the vuln on the unpatched tree?
- **Merge-ready rate**: % of bundles that pass Steward policy on first try.
- **False-positive rate**: % of findings for which no real vulnerability existed in the pinned rev.
- **Regression rate**: % of patches that broke downstream builds.
- **Human-seconds-to-merge**: measured on the subset reviewed by a human.

v0 ship gate: ≥60% merge-ready, <5% regression, reproducer fidelity ≥90%.

### 5a. Eval corpus construction (critical path, precedes agent work)

The 50-CVE corpus is the project's ground truth. If it's cherry-picked, every downstream metric is theater. The corpus is constructed **before** Patcher/Reviewer prompts are written, and each CVE is classified on six axes:

| Axis | Values | Why it matters |
|---|---|---|
| CPE/PURL mapping difficulty | easy / medium / ambiguous | Stresses Scout confidence scoring |
| Version-bump complexity | patch release / point release / multi-release / major jump | Stresses §2a upstream-fix rules |
| Existing `passthru.tests` | yes / minimal / none | Determines v0 eligibility |
| Reproducibility | straightforward / config-sensitive / DoS-shaped / crypto-shaped / parser-heavy / kernel-adjacent / impractical | Known-hard reproducer categories should be represented, not excluded |
| Rebuild closure size | <50 / 50–500 / 500–5000 / >5000 | Stresses blast-radius gate |
| Expected human decision difficulty | trivial / routine / contentious | Stresses the review panel |

Corpus composition rules:
- Each axis must have ≥3 CVEs in every non-trivial bucket (no all-easy corpus).
- At least 10 CVEs must be expected to fail v0 eligibility gates (to verify the advisory-only path).
- Corpus is frozen and version-controlled before the first Patcher run. Changes to corpus require a spec-level amendment.
- The classification matrix ships in `eval/corpus.json` and is published with the research.

### 5b. Bundle acceptance rubric (human review panel)

The north-star "self-contained decision" metric is operationalized through a fixed scoring form. Every panelist fills this out per bundle:

```yaml
cve_id: CVE-2026-XXXXX
bundle_id: <hash>
panelist_id: <pseudonymous>
decision: merge | reject | escalate
confidence: 1-5                  # 1 = coin-flip, 5 = would stake reputation
time_to_decision_seconds: <int>
needed_external_access: yes | no # did you open a browser tab, rebuild locally, or consult anything outside the bundle?
missing_evidence:                # free-form list of what the bundle failed to supply
  - ...
primary_rejection_reason:        # if decision != merge, one of:
  # patch-incorrect | upstream-ref-weak | reproducer-unconvincing |
  # regression-risk | blast-radius | version-jump-unjustified |
  # provenance-gap | other
notes: <free-form>
```

Panel composition: ≥3 nixpkgs-literate reviewers (see §7 open question 5). Each bundle in the review subset is scored independently by at least 2 panelists. Inter-rater agreement is itself a reported metric — divergence on confidence or primary_rejection_reason is a signal about bundle ambiguity.

---

## 6. v0 scope — narrow, boring, measurable

v0 is intentionally a "boring first win." Pick the slice where upstream-fix integration is cleanest and expand only after the bundle loop is proven.

### 6.0 Build order (harness before prompts)

The project is built in this order, not in parallel. Each stage gates the next:

1. **Bundle schema** (`policy/bundle-schema.json`) and **replay manifest** (`replay.json` shape) — the contract every agent output must satisfy.
2. **Steward policy** (`policy/steward.rego`) — the deterministic merge gate, written against the schema.
3. **Eval corpus** (`eval/corpus.json`) — 50 CVEs classified per §5a, frozen before any agent runs.
4. **Replay harness** — can re-run a role against frozen inputs with swappable model / prompt / tool versions (§9).
5. **Bundle acceptance rubric tooling** (§5b) — scoring form + aggregation.
6. **Graph builder + Scout + Cartographer + UpstreamRefResolver** — deterministic data layer. UpstreamRefResolver in particular must be built and eval'd on the corpus before any Patcher work, since Patcher depends on its output as given truth.
7. **Patcher and Reviewer prompts v1, Reproducer** — only after everything above exists. Prompt iteration is then an empirical exercise against the harness, not vibes-based authorship.

This locks the project around **evidence quality**, not model behavior. Once the harness exists, model choice becomes an empirical config problem — which is exactly where §0 wants it.

**The v0 slice (all four gates required):**
1. **Channel**: `nixos-unstable` only.
2. **Packages**: derivations that already have a `passthru.tests` entry.
3. **Patch style**: upstream release or tag fixes only. No cherry-picks, no backports, no agent-original patches.
4. **Blast radius**: rebuild closure below a fixed threshold (v0 default: 500 reverse-closure derivations). Anything over → human review queue.

**In scope:**
- Graph builder over a pinned `nixos-unstable` rev.
- Scout for NVD + GHSA with CPE/PURL confidence scoring and a mapping-failures queue.
- Role contracts and a capability-routing config (§1.2).
- Patcher + Reviewer + Steward agents with v1 prompts; Patcher/Reviewer enforced to different model families.
- Reproducer: both lanes required for auto-merge — existing `passthru.tests` run as regression check, plus an agent-generated vuln-specific `reproducer.nix` that fails on unpatched / passes on patched. CVEs where no vuln-specific reproducer can be generated are emitted as advisory-only findings.
- Replay harness (§9) and eval corpus of 50 historical CVEs replayable end-to-end.
- GitHub Actions orchestration against the fork.
- Bundle schema with the maintainer-centric fields (update rationale, passthru tests result, rebuild blast radius, Builder result, maintainer ownership, "why this version").

**Out of scope for v0:**
- Upstreaming to nixpkgs.
- master or stable channels.
- Derivations without `passthru.tests` (advisory-only findings emitted, no patch attempted).
- Cherry-pick/backport patch styles.
- Agent-original patches (no upstream ref).
- OSV feed, language-ecosystem feeds (npm/PyPI advisories) beyond what flows through GHSA.
- Hydra migration.
- Version-currency agent.
- Novel-vuln-discovery lane.
- UI. Bundles are files; review happens in GitHub PRs.

---

## 7. Open questions (decide before build)

Resolved:
- ~~Fork target~~ → `nixos-unstable` (§6 gate 1).
- ~~Reproducer coverage~~ → advisory-only for derivations without `passthru.tests` or without a vuln-specific reproducer (§2.2, §6).
- ~~Quarantine queue for no-upstream patches~~ → not a v0 problem; agent-original patches are out of scope entirely (§6 gate 3).

Still open:
1. **Capability routing config v0 defaults**: the first qualified cross-family Patcher/Reviewer pair is determined by eval against the frozen corpus (§5a). No model is named in advance. At least two qualified families must clear the eval bar before v0 ships to honor the monoculture principle (§0.5).
2. **Signing identity**: sigstore OIDC via GitHub, or Ad Astra-held key? OIDC is easier; held key is more defensible for a research artifact.
3. **CPE/PURL mapping confidence threshold**: what auto-advance cutoff? Too high and coverage collapses; too low and the queue is noise. Tune against the eval corpus.
4. **Rebuild-closure threshold**: the 500-derivation number is a guess. Calibrate from the eval corpus before ship.
5. **Bundle reviewer panel for the north-star metric**: who are the humans that generate the "decision-time + decision-confidence" data? Need at least 3 nixpkgs-literate reviewers willing to participate.

---

## 8. Success criteria (research, not product)

trace is a research artifact. It succeeds if, within 6 months of v0, we can answer with data:

- How often can agents turn a known upstream fix into a **maintainer-trustworthy** nixpkgs evidence bundle, measured against a human review panel's accept/reject and decision-time?
- Where do they fail — CPE mapping, minimality, reproducer fidelity, downstream breakage, upstream-ref misattribution?
- What prompt / tool / model / routing changes move the merge-ready rate on the replay corpus?
- Is the evidence-bundle format demonstrably faster and higher-confidence for human maintainers than the status quo PR?

Publish findings regardless of outcome. A well-documented negative result is the point of research.

---

## 9. Replayability

Every bundle is a reproducible scientific artifact. Each bundle records, and the replay harness can reconstruct end-to-end:

- **nixpkgs rev** (exact commit hash of the fork at the time of the run)
- **prompt hash** per role (content-addressed; `prompts/patcher.v1.md` sha256)
- **model/provider metadata** per role: vendor, model ID, full version string, sampling params, any routing flags
- **tool versions** for every CLI the agents invoked (captured via `nix develop` lockfile + explicit tool-version manifest)
- **policy version** (Steward `steward.rego` hash + bundle-schema hash)
- **input snapshot**: the exact CVE record, finding.json, impact.json the role saw
- **RNG seeds** where applicable

`trace replay <bundle-id> --role <role> --model <model-id>` re-runs a single role against the frozen inputs with a different model. For multi-role or full-pipeline replay, `trace replay <bundle-id> --routing-config <path>` applies a routing config across all roles. Single `--model` without `--role` is rejected as ambiguous. This is how challenger-model evals and prompt upgrades are validated: not vibes, not eyeballing diffs, but measured deltas against frozen inputs.

The replay corpus is versioned and public (within the research fork). Regression dashboards plot merge-ready rate, regression rate, reproducer fidelity, and decision-time per (model × prompt-version × policy-version) tuple over time. A model that improves patch rate but increases false-confidence (reviewer-accept / human-reject divergence) is auto-quarantined from routing until investigated.
