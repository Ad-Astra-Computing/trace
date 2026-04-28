# trace

Agent-owned nixpkgs fork for merge-ready CVE evidence bundles. See
[SPEC.md](SPEC.md) for the v0 design and [docs/](docs/) for component
specs (Builder, Reproducer, Steward, Signing, Model Eval Plan).

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
