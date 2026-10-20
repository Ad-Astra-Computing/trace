{
  description = "trace — agent-owned nixpkgs fork for merge-ready CVE evidence bundles";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        pythonEnv = pkgs.python3.withPackages (ps: [
          ps.pytest
          ps.jsonschema
          ps.referencing
          ps.anthropic
          ps.openai
        ]);

        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          # traces/, eval/experiments/ and tests/fixtures/ are model-authored
          # evidence bound to replay.json hashes. Formatting them would break
          # bundle provenance, so they are excluded from every formatter.
          settings.global.excludes = [
            "traces/**"
            "eval/experiments/**"
            "tests/fixtures/**"
          ];
          programs = {
            nixfmt.enable = true;
            ruff.format = true;
          };
        };
      in
      {
        formatter = treefmtEval.config.build.wrapper;

        # The CLI the docs call `trace` was never packaged, so every real
        # invocation (CI, README examples) resorted to spelling out
        # `python3 -m tools.trace_cli`. This wraps that exact invocation,
        # pinned to this flake's own source tree for provenance, so `nix
        # build` and `nix run` produce the binary the docs already name.
        packages.default =
          (pkgs.writeShellScriptBin "trace" ''
            export PYTHONPATH="${self}:$PYTHONPATH"
            exec ${pythonEnv}/bin/python3 -m tools.trace_cli "$@"
          '').overrideAttrs
            (_: {
              meta.homepage = "https://trace.adastra.computer";
              meta.description = "Agent-owned nixpkgs fork for merge-ready CVE evidence bundles";
            });

        checks.formatting = treefmtEval.config.build.check self;

        checks.eval-fixtures = pkgs.runCommand "eval-fixtures" { } ''
          cd ${self}
          PYTHONPATH=${self} TRACE_ROOT=${self} ${pythonEnv}/bin/python3 -m pytest -q -p no:cacheprovider tests/schema/test_fixtures.py tests/docs/test_seed_index.py
          touch $out
        '';

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
            # archive formats the bundle tooling extracts: .tar.lz (wget), .zip
            pkgs.lzip
            pkgs.gnutar
            pkgs.unzip
          ];

          shellHook = ''
            export TRACE_ROOT="$PWD"
            # Banner -> stderr so `nix develop --command python ... > file.txt`
            # captures only the program's output, not the shell hello.
            {
              echo "trace dev shell"
              echo "  python: $(python3 --version)"
              echo "  pytest: $(pytest --version 2>&1 | head -1)"
              if command -v opa >/dev/null 2>&1; then
                echo "  opa:    $(opa version | head -1)"
              else
                echo "  opa:    NOT ON PATH (Steward tests will skip)"
                echo "          install: curl -fsSL https://openpolicyagent.org/downloads/latest/opa_$(uname -s | tr A-Z a-z)_$(uname -m | sed s/x86_64/amd64/)_static -o ~/.local/bin/opa && chmod +x ~/.local/bin/opa"
              fi
            } >&2
          '';
        };

        # LoRA training shell, opt-in via `nix develop .#lora`.
        # Provides HuggingFace / TRL stack for Reviewer-LoRA v1.0 fine-tune.
        # On a cloud CUDA box without Nix, use: pip install -r lora/requirements-hf.txt
        devShells.lora =
          let
            loraEnv = pkgs.python3.withPackages (ps: [
              ps.transformers
              ps.peft
              ps.trl
              ps.datasets
              ps.accelerate
              ps.huggingface-hub
              ps.bitsandbytes
              # torch: nixpkgs ships the CPU build; CUDA variant requires
              # override or pip on the target GPU machine.
              ps.torch
              # keep base trace deps so eval/package_lora.py runs in this shell
              ps.pytest
              ps.jsonschema
              ps.referencing
            ]);
          in
          pkgs.mkShell {
            name = "trace-lora";
            packages = [
              loraEnv
              pkgs.jq
              pkgs.git
              pkgs.coreutils
            ];
            shellHook = ''
              export TRACE_ROOT="$PWD"
              {
                echo "trace lora dev shell"
                echo "  python:       $(python3 --version)"
                echo "  transformers: $(python3 -P -c 'import transformers; print(transformers.__version__)' 2>/dev/null || echo missing)"
                echo "  trl:          $(python3 -P -c 'import trl; print(trl.__version__)' 2>/dev/null || echo missing)"
                echo "  peft:         $(python3 -P -c 'import peft; print(peft.__version__)' 2>/dev/null || echo missing)"
                echo ""
                echo "  Prepare data: bash lora/prepare_mlx_data.sh"
                echo "  Train:        python3 lora/hf_train.py"
              } >&2
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
      }
    );
}
