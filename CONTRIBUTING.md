# Contributing to trace

Thanks for thinking about contributing. trace is a small, opinionated security-research project; the contribution surface is correspondingly narrow.

## Before you open a PR

1. **Read the contracts.** [`docs/CONCEPTS.md`](docs/CONCEPTS.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) cover the *what* and *where*. Per-role contracts (`docs/BUILDER_V1.md`, `REPRODUCER_V1.md`, `STEWARD_V1.md`, `SIGNING_V1.md`) cover *how each role behaves*. The append-only [`docs/DECISIONS.md`](docs/DECISIONS.md) covers *why each lock was set*. Most surprises in the codebase are documented there.
2. **Tests are the contract.** Every behavioural change ships with tests in `tests/` mirroring the agents/ or tools/ subdir you touched. `nix develop --command python3 -m pytest` should be green before you push.
3. **Schema and policy are first-class.** If you change a JSON file's shape, the matching schema in `policy/<file>-schema.json` changes too. If you change a Steward rule, the test in `tests/steward/` changes too.

## What kinds of changes are welcome

* **New role implementations** that conform to the documented contracts (e.g. an additional Reproducer adapter for a different model family).
* **New corpus bundles** for sandbox-positive CVE classes. See [`traces/example/CVE-2024-13978--libtiff/README.md`](traces/example/CVE-2024-13978--libtiff/README.md) for the deterministic-no-model corpus seed shape.
* **Schema tightening**: more invariants enforced earlier, fewer chances for a malformed bundle to reach Steward.
* **Steward rule additions** that close a real gap, with a fixture under `traces/example/CVE-0000-XXXX--<reason>/` demonstrating the gap.
* **Documentation fixes**, especially places where the docs and the code disagree.
* **Reproducer experiments**: prompt-iteration data, refusal-pattern analysis, model-eval extensions. See `eval/` and [`docs/MODEL_EVAL_PLAN.md`](docs/MODEL_EVAL_PLAN.md).

## What kinds of changes need discussion first

Open an issue or a discussion before writing the code if you want to:

* Change the locked routing config (`policy/routing-config.json`). Models there are pinned and changing them affects every replay.
* Change the signing identity (`policy/signing-identity.json`). The regex and the OIDC issuer are load-bearing for every existing signed bundle.
* Touch [`docs/DECISIONS.md`](docs/DECISIONS.md). It's append-only; corrections are amendments, not rewrites.
* Add a new model adapter to `agents/patcher/adapter.py`. Sampling defaults are deliberate.
* Add or remove a Steward rule. The rule numbering is stable; new rules get the next number, removed rules stay deprecated rather than vanish.

## Inbound license

By submitting a contribution, you agree your contribution is licensed under [Apache License 2.0](LICENSE), the same license as the rest of trace. We use the [Developer Certificate of Origin](https://developercertificate.org/) for sign-off; commits must include a `Signed-off-by: ...` line, which `git commit -s` adds automatically.

## Commit style

* **Conventional commits**, short subject (under 50 chars when possible), imperative mood, no period. Body explains *why*, not *what*, the diff already covers what.
* **Sign your commits.** Both GPG (via `git commit -S`) and DCO sign-off (`-s`) are required for changes that touch `policy/`, `prompts/`, or `.github/workflows/`. Other directories require sign-off only.
* **No `Co-Authored-By: Claude` or other AI-generation tags** in commit metadata. The diff and the work stand on their own; provenance lives in commit content + signing, not in trailer prose.
* **No em-dashes in user-facing copy** (docs, READMEs, prompts, commit messages, release notes). Em-dashes are a strong AI-writing tell. Use commas, colons, periods, parentheses, or middle dots.
* **Date format**: day before month (`13 March 2026`, not `March 13, 2026`).

## Security-sensitive contributions

If your contribution touches the signing path, the Rego policy, the schema enforcement, or anything that affects what gets attested under the locked workflow identity, please mention this in the PR description. We may ask for a longer review window and a second reviewer.

If you are reporting a security issue rather than fixing one, please use [`SECURITY.md`](SECURITY.md), not a public PR or issue.

## Code of conduct

Be technical, be specific, be respectful. Disagreements about design tradeoffs are fine and welcome; ad hominem and dismissiveness are not. We follow the [Contributor Covenant](https://www.contributor-covenant.org/) in spirit; the repo will adopt a formal Code of Conduct when the contributor base is large enough that "in spirit" no longer suffices.

## Local development

```sh
nix develop                  # default Python + tooling shell
nix develop .#graph          # Rust shell for the graph crate
python3 -m pytest            # full Python test suite
opa test policy/             # Rego policy tests (when present)
```

Pre-commit hooks (gitleaks + light hygiene) run locally; install via `pre-commit install` from inside `nix develop`. The hooks must pass before any push; do not bypass with `--no-verify`.
