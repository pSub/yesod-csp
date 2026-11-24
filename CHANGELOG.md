# Changelog

## Unreleased

+ **Breaking:** `BaseUri` now takes a `SourceList` instead of an `EscapedURI`, so `base-uri 'none'` and `base-uri 'self'` can be expressed
+ Add hash sources, `'unsafe-hashes'` and `'wasm-unsafe-eval'`
+ Add `upgrade-insecure-requests`, `require-trusted-types-for` and `trusted-types`
+ Add the remaining sandbox flags, such as `allow-popups` and `allow-modals`
+ Add `cspPolicyReportOnly` and `cspMiddlewareReportOnly` for `Content-Security-Policy-Report-Only`
+ Add `cspWarnings`, which lists risky combinations such as `data:` in `script-src`
+ `escapeAndParseURI` keeps a leading `*.` in the host, so wildcard subdomains such as `https://*.example.com` can be expressed

## Version 0.2.9.0

+ Fix directive injection via `report-to`: characters that are not valid in an HTTP token are now dropped from the group name
+ Restrict nonces to base64 and base64url characters; commas, line breaks and other characters are now dropped
+ Escape commas in URIs so they can no longer split the header into several policies
+ Add `getCspNonce`, which returns a random nonce per request, and use it in the examples instead of a fixed nonce
+ Accept the standard quoted keywords `'unsafe-inline'`, `'unsafe-eval'` and `'strict-dynamic'` in the `csp` quasi-quoter
+ Stop rendering a trailing space for `MetaSource`
+ Document that `*` and `'none'` drop other sources, that `plugin-types` and `prefetch-src` are obsolete, and that `cspMiddleware` keeps headers set by handlers

## Version 0.2.8.0

+ Add support for CSP Level 3 directives: `report-to`, `worker-src`, `manifest-src` and `prefetch-src`

## Version 0.2.7.1

+ Relax version boundaries on template-haskell to be able to build with ghc-9.10 on nixos-25.11

## Version 0.2.7.0

+ Add support for remaining CSP Level 2 directives (see https://github.com/pSub/yesod-csp/pull/5)

## Version 0.2.6.0

+ Fixes compilation failure with ghc-9.0.2 or newer (see https://github.com/bobjflong/yesod-csp/issues/8)
