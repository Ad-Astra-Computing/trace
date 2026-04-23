# trace-graph-builder

Rust crate that produces `policy/graph-snapshot-schema.json`-shaped JSON over
stdout. v0 is a **stub**: no nixpkgs evaluation, no eval cache walk, no
maintainer extraction. It emits a single-node snapshot to prove the
binary-and-schema boundary.

## Build & run

```
cargo build --release --manifest-path graph/Cargo.toml
./graph/target/release/trace-graph-builder
./graph/target/release/trace-graph-builder --rev 0000000000000000000000000000000000000000
cargo test --manifest-path graph/Cargo.toml
```

## Why not in the default devShell?

`pkgs.rustc` + `pkgs.cargo` rebuild cleanly on darwin-arm64 under nixpkgs
(binary-cache hits), but adding them pulls ~1 GB of toolchain into every
`nix develop` entry. For v0 the graph binary is only built when someone is
actively working on it. Install Rust via your preferred method (`rustup`,
`nix shell nixpkgs#rustc nixpkgs#cargo`, brew, ...) or see the optional
`graph` devShell in `flake.nix`.

## Validation

The Python test at `tests/graph/test_graph_snapshot.py` runs `cargo run`
(skipping if `cargo` is absent) and validates the emitted JSON against
`policy/graph-snapshot-schema.json`. CI can add a dedicated job that sets
`TRACE_REQUIRE_CARGO=1` to fail instead of skip.

## Roadmap (explicitly not v0)

- Nix derivation-graph walk (nix-instantiate / evaluate).
- Reverse-closure computation at scale.
- SQLite / Parquet snapshot output in addition to JSON.
- Maintainer extraction from `maintainers/maintainer-list.nix`.
- Critical-downstream policy (manual list, then heuristic).
