# trace

Agent-owned nixpkgs fork for merge-ready CVE evidence bundles.

**Start here:**

* [docs/CONCEPTS.md](docs/CONCEPTS.md), what trace is + the key concepts (bundles, roles, kinds, cross-family rule, signing).
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), directory layout + control flow + what pins what.
* [docs/SEED_INDEX.md](docs/SEED_INDEX.md), one-page map of the eight real-CVE bundles in `traces/example/`: kind, provenance family, what each demonstrates.
* [SPEC.md](SPEC.md), v0 design, rev 3 (22 April 2026).

**Deep dives:** per-role contracts under [docs/](docs/) (`BUILDER_V1.md`, `REPRODUCER_V1.md`, `STEWARD_V1.md`, `SIGNING_V1.md`), the append-only decision log at [docs/DECISIONS.md](docs/DECISIONS.md), and model-qualification methodology at [docs/MODEL_EVAL_PLAN.md](docs/MODEL_EVAL_PLAN.md). Tagged release notes live at [CHANGELOG.md](CHANGELOG.md).

## Development

The default dev shell lives in `flake.nix`:

```sh
nix develop
```

Tests:

```sh
pytest
```

The Rust graph crate has its own shell, opt-in via `nix develop .#graph`.

## Verifying a signed bundle

Every bundle Steward signs anchors a Rekor transparency-log entry to a locked workflow identity (`policy/signing-identity.json`). Verify a downloaded artifact with:

```sh
gh run download <run-id> --name steward-smoke-<bundle> --dir ./artifact
trace bundle verify ./artifact
```

cosign must be on PATH. The artifact dir must contain `bundle.canonical.json` (the frozen pre-sign snapshot, the actual signed bytes) and `bundle.sig`. Background and the full identity-pinning rationale: [docs/SIGNING_V1.md](docs/SIGNING_V1.md) §5.

## Pre-commit hooks

Local hooks run a secret scanner (gitleaks) plus light hygiene checks.
While the repo is private, GitHub's free secret scanning is not
available, so the local hook is the safety net before anything reaches
origin. To enable, install [pre-commit](https://pre-commit.com) (it is
on PATH inside `nix develop`, or `pipx install pre-commit` works too),
then run `pre-commit install` once in the repo root to wire up the git
hook. Run `pre-commit run --all-files` to scan the whole tree on
demand. Path allow-lists for public CVE/GHSA fixtures live in
`.gitleaks.toml`.
