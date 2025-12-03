{ compiler ? "ghc910", nixpkgs ? import <nixpkgs> {} }:
nixpkgs.pkgs.haskell.packages.${compiler}.callPackage ./yesod-csp.nix { }
