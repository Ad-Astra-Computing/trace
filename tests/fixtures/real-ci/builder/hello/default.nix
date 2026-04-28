# Bundle-local default.nix for the builder.yml smoke fixture.
#
# Builder's patched-build phase invokes `nix-build --no-out-link -A <attr>`
# in the bundle directory when nixpkgs_checkout is not supplied.
# This default.nix re-exports the `hello` attr from <nixpkgs> so the
# patched-build phase produces a real store path without requiring a
# full nixpkgs checkout. Sufficient for a Nix-availability + plumbing
# smoke; not intended to substitute for a real nixpkgs-rooted build.
{ pkgs ? import <nixpkgs> { } }:

{
  hello = pkgs.hello;
}
