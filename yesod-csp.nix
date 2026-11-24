{ mkDerivation, attoparsec, base, base64-bytestring, case-insensitive
, entropy, hspec, lib
, mono-traversable, network-uri, semigroups, syb, template-haskell
, text, wai, wai-extra, yesod, yesod-core, yesod-test, mime
}:
mkDerivation {
  pname = "yesod-csp";
  version = "0.2.8.0";
  src = ./.;
  isLibrary = true;
  isExecutable = false;
  libraryHaskellDepends = [
    attoparsec base base64-bytestring case-insensitive entropy
    mono-traversable network-uri
    semigroups syb template-haskell text wai yesod yesod-core mime
  ];
  testHaskellDepends = [
    attoparsec base hspec network-uri semigroups template-haskell text
    wai-extra yesod yesod-test
  ];
  description = "Add CSP headers to Yesod apps";
  license = lib.licenses.mit;
}
