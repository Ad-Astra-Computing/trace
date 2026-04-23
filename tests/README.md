# trace tests

Two layers:

1. **Schema layer** (`tests/schema/`) — JSON Schema validation of every document in each fixture. Pure Python, requires only `nix develop`.
2. **Steward layer** (`tests/steward/`) — OPA-driven policy evaluation of `policy/steward.rego` against each schema-valid fixture. Requires the `opa` binary on PATH.

## Setup

```
nix develop
```

This provides `python3` with `pytest`, `jsonschema`, and `referencing`. No venv, no pip.

## Run

```
pytest
```

Locally that will give you every schema test plus every Steward test where `opa` is available. Schema-invalid fixtures are auto-skipped by the Steward runner.

## OPA (required for Steward layer)

### What `pytest` does when opa is missing

The Steward runner calls `opa version` at session start. If the binary is not on PATH:

- Steward tests are **skipped**, not failed. Schema layer still runs in full.
- This is intentional so local development is not blocked by OPA absence.

### CI must fail instead of skip

Local tolerance of a missing OPA does not weaken the project's merge gate. Any CI that exercises this suite **must install opa explicitly and fail the job if `opa version` does not succeed before pytest runs.** A silent skip in CI is a silent regression in Steward coverage. Prefer a literal preflight step:

```
command -v opa >/dev/null || { echo "opa missing in CI"; exit 1; }
opa version
pytest
```

Future improvement: gate this with an env var (e.g. `TRACE_REQUIRE_OPA=1 pytest`) that flips the Steward runner from skip to fail. Not yet wired; track as a follow-up.

### Installing opa via nix

Intentionally kept out of `flake.nix`'s devShell because `pkgs.open-policy-agent` has no darwin-arm64 binary cache hit on our pinned nixpkgs and rebuilds from Go source — about 15 minutes on first entry, which blocks every `nix develop`.

Install it once into your user profile and let it live alongside other nix-managed tools:

```
nix profile install nixpkgs#open-policy-agent
```

First invocation on darwin-arm64 will still rebuild from source once; subsequent shells are instant. On linux-x86_64 the binary cache usually hits and the install is near-instant.

For a one-shot session without polluting your profile:

```
nix shell nixpkgs#open-policy-agent --command pytest
```

(Same first-build caveat applies.)

## Strict hash mode

By default, fixture sha256 values are placeholders and are not checked against actual file bytes — only schema shape is validated. To enforce real hashes:

```
TRACE_STRICT_HASHES=1 pytest
```

Under strict mode, every file referenced in a fixture's `bundle.json` must exist on disk and hash to the declared sha256. This mode becomes default once the bundle-production pipeline writes real hashes.

## Eval-corpus composition mode

`tests/eval/test_corpus.py` runs in two layers:

- **Shape layer** always runs: corpus schema well-formedness, `eval/corpus.json` validates against the schema, axis-value cross-check.
- **Composition layer** runs only when the corpus is frozen (`eval/corpus.json` has `"status": "frozen"`) OR when the env var is set:

```
TRACE_REQUIRE_FULL_CORPUS=1 pytest tests/eval
```

Composition rules enforce SPEC §5a: ≥50 non-example entries, no duplicate CVE ids, every declared axis value is used, ≥3 entries per non-trivial bucket, ≥10 entries expected to fail v0 eligibility gates, every real entry has `historical_fix`. The seed file will fail these until the real corpus lands; that failure is the point.

## Fixture layout

```
traces/example/<fixture-name>/
├── expect.json              # see below
├── bundle.json              # validated against bundle-schema.json
├── finding.json             # validated against finding-schema.json
├── upstream-ref.json        # validated against upstream-ref-schema.json
├── replay.json              # validated against replay-schema.json
├── provenance.jsonl         # each line validated against provenance-line-schema.json
└── (other bundle files)
```

### `expect.json` shapes

Three categories, matched by the test runners:

- **Positive** — schema passes and Steward allows:
  ```json
  { "overall": "valid" }
  ```
- **Schema-negative** — one declared document fails JSON Schema validation:
  ```json
  {
    "overall": "invalid",
    "expected_failure": { "doc": "bundle.json", "rule": "..." }
  }
  ```
  The Steward runner skips these; they never reach policy.
- **Steward-negative (cross-document)** — every document is schema-valid, but Steward denies on a cross-document invariant:
  ```json
  {
    "overall": "valid",
    "steward_expected": "invalid",
    "steward_rule_id": "rule-5-provenance-replay-must-agree",
    "steward_rule": "..."
  }
  ```
  `steward_rule_id` must match the prefix used by `policy/steward.rego`.

## Layer boundary

JSON Schema validates single-document shape. Steward (OPA) validates cross-document bundle semantics. The schema runner does **not** perform cross-document checks; keeping the boundary sharp means failures are interpretable and each layer evolves independently.
