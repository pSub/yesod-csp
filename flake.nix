{
  description = "yesod-csp";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        yesod-csp = pkgs.callPackage ./default.nix { nixpkgs = pkgs; };
      in
      {
        packages.yesod-csp = yesod-csp;
        packages.default = yesod-csp;
        devShells.default = yesod-csp.env.overrideAttrs (old: {
          nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.cabal-install ];
        });
      }
    );
}
