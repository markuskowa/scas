{
  description = "Simple content addressed storage";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }: {

    packages = let
      forAllSystems = function:
        nixpkgs.lib.genAttrs [
          "x86_64-linux"
          "aarch64-linux"
      ] (system: function nixpkgs.legacyPackages.${system} system);

    in forAllSystems (pkgs: system: {
      default = pkgs.callPackage ./package.nix {};
    });
  };
}
