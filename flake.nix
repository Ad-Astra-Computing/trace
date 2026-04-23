{
  description = "trace — agent-owned nixpkgs fork for merge-ready CVE evidence bundles";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        pythonEnv = pkgs.python3.withPackages (ps: [
          ps.pytest
          ps.jsonschema
          ps.referencing
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          name = "trace";
          packages = [
            pythonEnv
            pkgs.jq
            pkgs.git
            pkgs.coreutils
            # open-policy-agent is kept out of the flake intentionally: it has
            # no darwin-arm64 binary cache hit and rebuilds from Go source,
            # which blocks `nix develop` for ~15 minutes. Install opa however
            # you prefer (brew, curl, or a one-off nix-shell) and ensure it is
            # on PATH. The Steward test runner pytest.skips if opa is missing.
            #
            # rustc + cargo are kept out of the default shell to keep entry
            # fast. Use `nix develop .#graph` when working on the graph crate.
          ];

          shellHook = ''
            export TRACE_ROOT="$PWD"
            echo "trace dev shell"
            echo "  python: $(python3 --version)"
            echo "  pytest: $(pytest --version 2>&1 | head -1)"
            if command -v opa >/dev/null 2>&1; then
              echo "  opa:    $(opa version | head -1)"
            else
              echo "  opa:    NOT ON PATH (Steward tests will skip)"
              echo "          install: curl -fsSL https://openpolicyagent.org/downloads/latest/opa_$(uname -s | tr A-Z a-z)_$(uname -m | sed s/x86_64/amd64/)_static -o ~/.local/bin/opa && chmod +x ~/.local/bin/opa"
            fi
          '';
        };

        # Graph-crate shell, opt-in via `nix develop .#graph`. Adds the Rust
        # toolchain; default shell stays fast.
        devShells.graph = pkgs.mkShell {
          name = "trace-graph";
          packages = [
            pythonEnv
            pkgs.jq
            pkgs.git
            pkgs.coreutils
            pkgs.rustc
            pkgs.cargo
          ];
          shellHook = ''
            export TRACE_ROOT="$PWD"
            echo "trace graph dev shell"
            echo "  rustc: $(rustc --version)"
            echo "  cargo: $(cargo --version)"
          '';
        };
      });
}
