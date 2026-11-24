# Changelog

## Unreleased

+ **Breaking:** `BaseUri` now takes a `SourceList` instead of an `EscapedURI`, so `base-uri 'none'` and `base-uri 'self'` can be expressed
+ Add hash sources, `'unsafe-hashes'` and `'wasm-unsafe-eval'`
+ Add `upgrade-insecure-requests`, `require-trusted-types-for` and `trusted-types`
+ Add the remaining sandbox flags, such as `allow-popups` and `allow-modals`
+ Add `cspPolicyReportOnly` and `cspMiddlewareReportOnly` for `Content-Security-Policy-Report-Only`
+ `escapeAndParseURI` keeps a leading `*.` in the host, so wildcard subdomains such as `https://*.example.com` can be expressed

## Version 0.2.8.0

+ Add support for CSP Level 3 directives: `report-to`, `worker-src`, `manifest-src` and `prefetch-src`

## Version 0.2.7.1

+ Relax version boundaries on template-haskell to be able to build with ghc-9.10 on nixos-25.11

## Version 0.2.7.0

+ Add support for remaining CSP Level 2 directives (see https://github.com/pSub/yesod-csp/pull/5)

## Version 0.2.6.0

+ Fixes compilation failure with ghc-9.0.2 or newer (see https://github.com/bobjflong/yesod-csp/issues/8)
