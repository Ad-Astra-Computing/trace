# Changelog

Append-only release notes. Tagged releases land at the top; unreleased work accumulates under a `Unreleased` heading until a tag cuts.

---

## v1.0.0 — 20 October 2026

### Public release: a live-CVE lane, a signing-chain audit and an honest accuracy number

v1.0.0 is the first public tag. The corpus holds 113 tracked bundles, 86 of
them cert-green as of 8 October. A blind authoring run against 41 real
upstream backports put the model at 39 percent exact or equivalent to the
human fix, the number this release states instead of a frontier-parity claim.
Findings, cost breakdowns and the full bundle corpus are now at
[trace.adastra.computer](https://trace.adastra.computer).

**A live lane patches fresh CVEs instead of ones nixpkgs has already fixed.**
Scout screens live advisories through a fifth precision gate, on ecosystem. A
comparison watcher grades each resulting bundle against whatever nixpkgs
eventually lands for the same CVE, not against a pull request. A CVE class
that admits no sandbox reproducer routes through a reviewer-attested path
instead of a fabricated one, and stub-harness fixtures let a flaw in a request
parser or a renderer get a real proof under a stubbed host.

**An audit of the signing chain found a gap and closed it.** The tool that
opens fork review pull requests trusted each bundle's own mutable,
self-reported hashes instead of its signed manifest; fixed in commit
`41a383d3`, then checked against the whole signed set. Five bundles had
drifted after signing with no new signature; one has since been re-signed,
with the old signature's coordinates kept on record (`535a6efd`).

**A reproducer's own claim of success had to start surviving a build.** Two
cases shipped a log describing a result the sandbox never produced. Both were
caught by a bounded two-arm `nix-build` probe that now runs before a bundle
reaches cert, in place of trusting the model's own account.

**Two throughput fixes landed in this window.** The nix-seed discovery lane
had stalled silently: its process cap went entirely to NVD discoveries, so
the emitted backlog never got a processing slot. `scout-cron`
now splits the cap into a reserved nix-seed share and a retry-plus-NVD share,
with two-way backfill so neither lane starves. `trace report throughput`
gained a cost-by-kind breakdown: auto-merge bundles and human-review-required
bundles cost about the same per bundle to produce, so the corpus spends
roughly 2.4 times as much in total on honest-refusal evidence as on
merge-ready bundles.

**The Reviewer-LoRA pilot on `Qwen2.5-Coder-14B-Instruct` is retired from the
production path.** It passed its small-fold gate and stays on record as a
cost-reduction experiment, but every bundle in this release was reviewed by a
frontier model; the pilot's numbers do not support the figures above.
