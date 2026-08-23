# Preregistration — cross-distro adaptation-yield screening study

**Registered before the run.** Purpose: decide, with a number instead of an
assumption, whether Debian CVE backport patches are a rich enough source of
GENUINE code adaptations to justify reviving the compound-guard successor arc
(halted 2026-08-09; see DECISIONS). The July `oracle-crossdistro-pilot.json`
fired a pre-registered STOP at 1/10 yield under a STRICTER (bundle-registration)
gate; this study re-measures under the LOOSER judgment-only gate the two peers'
reframe actually needs, using the codified verifier
(`scripts/harvest_oracle_candidates.py::verify_against_upstream`, validated
13/13 against the manual pass).

Design reviewed by the codex peer (2026-08-23, methodology framing).

## Estimand

Among Debian CVE patches that **cite a resolvable upstream commit**, the
fraction that are **genuine adaptations** (payload differs materially from the
cited upstream fix), as classified by `verify_against_upstream`.

The rate is CONDITIONAL on citing a resolvable ref — that is the only subset the
tool can compare. The fraction of sampled CVE patches that are citable is
reported SEPARATELY; the conditional rate must not be presented as the rate over
all Debian CVE patches. (Patches that do not cite a ref may skew MORE toward
adaptation — hand-written, no clean upstream — so the citable-subset rate is a
conservative lower bound for the "is cross-distro rich?" question.)

## Frame

- Census source: the Debian security-tracker JSON
  (`security-tracker.debian.org/tracker/data/json`), sha256 recorded.
- A candidate is a (source-package, CVE) pair where some `*-security` suite has
  `status: resolved` and records a source version. The security-suite version
  pins exactly where the backport patch lives on `sources.debian.org`.
- Eligibility (all must hold), evaluated at fetch time:
  1. A patch named `CVE-YYYY-NNNN.patch` exists under that version's
     `debian/patches/`. (Debian's dominant security-backport naming; a fixed,
     pre-committed rule — patches under other names are treated as
     non-citable-here and counted toward the eligibility denominator, not
     silently skipped.)
  2. Its header cites a resolvable upstream ref: a `github.com/<o>/<r>/commit/
     <sha>` URL, a `From <40-hex>` git format-patch line, or a
     gitweb/cgit `;h=<40-hex>` / `commit <40-hex>` reference on an
     allowlisted upstream host.
  3. The cited upstream patch is fetchable.
- **At most one patch per source package** (codex: package-clustered
  independence). If a sampled package's first drawn CVE is ineligible, the
  package is retried with its next CVE (deterministic order) up to a small cap,
  then abandoned — a package is counted once in the eligibility denominator.

## Sampling

- Patch-level pseudo-random draw over the census, seeded deterministically
  (`SEED=20260823`), so the run is reproducible and the sample is fixed before
  any verdict is seen.
- Draw until **41 ELIGIBLE patches** have been screened, or the candidate pool
  is exhausted. Record how many candidates were drawn to reach 41 (the
  eligibility rate).

## Ambiguous cases

`provenance-ambiguous` verdicts (payload overlap ≥ 0.85, non-identical:
possible branch-variant / squash) are reported as their OWN category. They are
NOT counted as genuine for the decision rule (conservative), and NOT counted as
verbatim. Reported separately, never silently dropped.

## Decision rule (binomial threshold, pre-committed)

Of the 41 eligible, let g = count classified `genuine-adaptation` (strictly;
ambiguous excluded).

- **g ≥ 8 → RICH.** Cross-distro yield is high enough that reviving the powered
  successor arc via cross-distro harvest is on the table (next step: a full
  harvester + the redesigned experiment prereg, both still Jason/peer-gated).
- **g ≤ 7 → THIN.** The peers' scale path is not supported by the data; the arc
  stays closed as a case-study resource. (At true rate 10% P(g≥8)≈4.8%; at true
  rate 30% P(g≤7)≈4.6% — codex.)

Report g, the verbatim count, the ambiguous count, the eligibility rate, and the
Wilson 95% CI on g/41 regardless of which side of the threshold it lands.

## Discipline

Offline-by-verifier: the classifier is pure text, no model, no execution. All
fetched text (Debian patches, upstream patches, tracker JSON) is treated as
untrusted DATA — allowlisted HTTPS hosts only, sha256 recorded per fetch, never
executed, never included in any model prompt. Debian hosts:
`security-tracker.debian.org`, `sources.debian.org`. Upstream forges are
allowlisted per cited host as encountered and recorded. No model spend.
