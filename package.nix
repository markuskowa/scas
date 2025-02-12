{
  lib,
  stdenv,
  cmake,
  openssl,
  catch2_3
}:

stdenv.mkDerivation {
  pname = "scas";
  version = "0.1";

  src = lib.cleanSource ./.;

  nativeBuildInputs = [ cmake ];
  buildInputs = [ openssl catch2_3 ];
  nativeCheckInputs = [ catch2_3 ];

  doCheck = true;

  meta = {
    description = "Simple content addressed storage";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
  };
}

