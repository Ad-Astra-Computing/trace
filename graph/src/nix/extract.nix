# trace-graph-builder — per-attr extraction expression.
#
# Single-argument function. All user-controlled data (nixpkgs path, attr
# list, system) arrives via a JSON spec file whose path is the ONLY string
# interpolated into the outer Nix invocation. The caller constructs the
# spec file under trace's own control (Rust tempdir) and passes its path
# in; the file's contents never flow through Nix expression source. This
# removes the code-eval attack surface on the --apply boundary.
#
# Spec shape (JSON):
#   {
#     "nixpkgsPath": "/nix/store/...-source",   // string, coerced to path by import
#     "attrs": ["hello", "python3Packages.requests", ...],
#     "system": "x86_64-linux"                   // optional; defaults to currentSystem
#   }
#
# Output (JSON list): one record per resolvable attr with attr_path, drv_path,
# pname, version, src_url, src_hash, build_inputs_drvs, maintainers. Unresolvable
# attrs are skipped silently so partial extraction stays useful.

{ specPath }:

let
  spec = builtins.fromJSON (builtins.readFile specPath);
  system = spec.system or builtins.currentSystem;

  pkgs = import spec.nixpkgsPath {
    inherit system;
    config.allowUnfree = true;
    config.allowAliases = false;
  };
  lib = pkgs.lib;

  byPath =
    attrPath:
    let
      parts = lib.splitString "." attrPath;
    in
    lib.attrByPath parts null pkgs;

  safeSrcUrl =
    src:
    if src == null then
      null
    else if src ? url then
      src.url
    else if src ? urls && builtins.isList src.urls && src.urls != [ ] then
      builtins.head src.urls
    else
      null;

  safeSrcHash =
    src:
    if src == null then
      null
    else if src ? hash then
      src.hash
    else if src ? outputHash then
      src.outputHash
    else
      null;

  asMaintainer = m: {
    github = m.github or null;
    email = m.email or null;
    name = m.name or null;
  };

  drvPathOr =
    x:
    if x == null then
      ""
    else if builtins.isAttrs x && x ? drvPath then
      x.drvPath
    else
      "";

  buildInputsDrvs =
    drv:
    let
      lists = [
        (drv.buildInputs or [ ])
        (drv.nativeBuildInputs or [ ])
        (drv.propagatedBuildInputs or [ ])
      ];
      flat = lib.concatLists lists;
      paths = map drvPathOr flat;
      nonEmpty = builtins.filter (p: p != "") paths;
    in
    lib.unique nonEmpty;

  extractOne =
    attrPath:
    let
      drv = byPath attrPath;
    in
    if drv == null || !(builtins.isAttrs drv) || !(drv ? drvPath) then
      null
    else
      {
        attr_path = attrPath;
        drv_path = drv.drvPath;
        pname = drv.pname or (lib.getName drv);
        version = drv.version or (lib.getVersion drv);
        src_url = safeSrcUrl (drv.src or null);
        src_hash = safeSrcHash (drv.src or null);
        build_inputs_drvs = buildInputsDrvs drv;
        maintainers = map asMaintainer (drv.meta.maintainers or [ ]);
      };

in
lib.filter (x: x != null) (map extractOne spec.attrs)
