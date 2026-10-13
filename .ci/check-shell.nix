# Native headers and runtime libraries for Linux verification.
{ pkgs ? import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz";
  sha256 = "sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=";
}) {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    openssl
    dbus
  ];
  nativeBuildInputs = with pkgs; [
    pkg-config
  ];
  # Test binaries link openssl and dbus dynamically without a runtime path.
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl pkgs.dbus ];
}
