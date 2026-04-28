{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.hello;
  patched = pkgs.hello;
in
{
  inherit unpatched patched;

  # Minimal reproducer for the builder.yml smoke. Both unpatched and
  # patched paths emit a synthetic signal substring; the goal is to
  # exercise LocalNixBuildRunner end-to-end (subprocess plumbing,
  # build.json shape, replay.json append), NOT to validate a real
  # vuln-specific test. A real reproducer would discriminate the
  # unpatched and patched runs; this one does not, by design — the
  # bundle is synthetic and there is no real CVE to discriminate.
  test = pkgs.runCommand "smoke-CVE-9999-99999" { } ''
    echo "vuln-triggered: synthetic-builder-smoke-signal-for-unpatched-run-discriminator"
    echo "rejected-malformed-input-as-expected-from-CVE-9999-99999-builder-smoke" > $out
  '';
}
