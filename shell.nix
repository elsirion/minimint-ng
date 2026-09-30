# Exact nixpkgs content pin; this is build infrastructure, not protocol code.
let
  pkgs = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/d6524aaca2ff07876657ae2b323f24be4874944b.tar.gz";
    sha256 = "sha256-2V9GZGvPfrNzxFozhI9dcqV+c3QdA8YZrvAAzqEB+dI=";
  }) {};
in pkgs.mkShell {
  packages = with pkgs; [ cargo rustc rustfmt clippy gcc python3 pkg-config openssl ];
}
