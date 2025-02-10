{
  nixpkgs ? <nixpkgs>
}:

let
  pkgs = import nixpkgs {};
  inherit (pkgs)
    lib
    stdenv
    cmake
    openssl
  ;

in stdenv.mkDerivation {
  pname = "scas";
  version = "dev";

  src = lib.cleanSource ./.;

  nativeBuildInputs = [ cmake ];
  buildInputs = [ openssl ];
}

