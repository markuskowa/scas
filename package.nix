{
  lib,
  stdenv,
  cmake,
  openssl,
  catch2_3
}:

stdenv.mkDerivation {
  pname = "scas";
  version = "0.2";

  src = lib.cleanSource ./.;

  nativeBuildInputs = [ cmake ];
  propagatedBuildInputs = [ openssl ];
  nativeCheckInputs = [ catch2_3 ];

  doCheck = true;

  meta = {
    description = "Simple content addressed storage";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
  };
}

