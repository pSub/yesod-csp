# yesod-csp

The aim of this library is to make it easy to add correct [Content Security Policy](https://content-security-policy.com/) headers to your responses. This reduces the risk of loading bad assets or scripts.

## Using the data types

The following code:

```haskell
getHomeR :: Handler Html
getHomeR = do
  cspPolicy [ScriptSrc (Self :| []), StyleSrc (Https :| [Self])]
  defaultLayout [whamlet|hello|]
```

will ensure that a `Content-Security-Policy: script-src 'self'; style-src https: 'self'` header is set. In this example we only want to load scripts from our own domain, and we only want styles that come from our domain or over https.

Use `getCspPolicy` to see the header a policy produces, and check that it matches what you need.

## Adding a policy to every response

`cspMiddleware` is a WAI middleware that adds the same policy to every response:

```haskell
main :: IO ()
main = toWaiApp App >>= run 3000 . cspMiddleware [DefaultSrc (Self :| [])]
```

A header set by a handler with `cspPolicy` is kept as well. The browser then enforces both policies, so a resource must be allowed by each.

## Nonces

A nonce only protects you if it is unpredictable and changes with every response. `getCspNonce` returns a random nonce for the current request, and returns the same value on every call within that request:

```haskell
getHomeR :: Handler Html
getHomeR = do
  n <- getCspNonce
  cspPolicy [ScriptSrc (nonce n :| [])]
  defaultLayout [whamlet|<script nonce=#{n}>alert("hi");|]
```

## Template Haskell support

The `csp` quasi-quoter from `Yesod.Csp.TH` lets you write policies in the familiar CSP syntax instead of building the data types yourself. The policy is parsed at compile time, so a malformed policy is a compile error:

```haskell
getHomeR :: Handler Html
getHomeR = do
  cspPolicy [csp|img-src 'self' https:; script-src https://foo.com|]
  ...
```

You can add URLs and nonces from the surrounding scope with `$`:

```haskell
getHomeR :: Handler Html
getHomeR = do
  let url = fromJust (escapeAndParseURI "https://cdn.example.com")
  n <- getCspNonce
  cspPolicy [csp|img-src 'self' $url; script-src $nonce-n|]
  ...
```

## Examples

[This module](https://github.com/pSub/yesod-csp/blob/master/src/Yesod/Csp/Example.hs) contains a host of runnable example Yesod handlers which set various CSP headers.
