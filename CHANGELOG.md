# Changelog

## Version 0.2.8.1

+ Fix directive injection via `report-to`: characters that are not valid in an HTTP token are now dropped from the group name
+ Restrict nonces to base64 and base64url characters; commas, line breaks and other characters are now dropped
+ Escape commas in URIs so they can no longer split the header into several policies

## Version 0.2.8.0

+ Add support for CSP Level 3 directives: `report-to`, `worker-src`, `manifest-src` and `prefetch-src`

## Version 0.2.7.1

+ Relax version boundaries on template-haskell to be able to build with ghc-9.10 on nixos-25.11

## Version 0.2.7.0

+ Add support for remaining CSP Level 2 directives (see https://github.com/pSub/yesod-csp/pull/5)

## Version 0.2.6.0

+ Fixes compilation failure with ghc-9.0.2 or newer (see https://github.com/bobjflong/yesod-csp/issues/8)
