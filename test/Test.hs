{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}

import           Codec.MIME.Parse          (parseMIMEType)
import           Codec.MIME.Type           (MIMEType (..), Type (..))
import           Data.Attoparsec.Text
import           Data.List.NonEmpty
import           Data.Maybe
import           Test.Hspec
import           Yesod                hiding (get)
import           Yesod.Csp
import           Yesod.Csp.TH
import           Yesod.Test

data Test = Test
mkYesod "Test" [parseRoutes|
/ HomeR GET
/nocsp NoCspR GET
/reportonly ReportOnlyR GET
|]

instance Yesod Test

getHomeR :: Handler Html
getHomeR = do
  cspPolicy [ScriptSrc (Self :| []), StyleSrc (Https :| [Self])]
  defaultLayout [whamlet|hello|]

getReportOnlyR :: Handler Html
getReportOnlyR = do
  cspPolicyReportOnly [ScriptSrc (Self :| [])]
  defaultLayout [whamlet|hello|]

getNoCspR :: Handler Html
getNoCspR = do
  defaultLayout [whamlet|hello|]

main :: IO ()
main = hspec $ tests >> middlewareTest

tests :: Spec
tests = yesodSpec Test $ do
  ydescribe "Generation" $ do
    yit "works" $ do
      let header = getCspPolicy [ScriptSrc (Self :| []), StyleSrc (Https :| [Self])]
      assertEq "simple header" header "script-src 'self'; style-src https: 'self'"
    yit "works with domains" $ do
      let dom = fromJust $ escapeAndParseURI "https://foo.com/bar *"
          header = getCspPolicy [ScriptSrc (Host dom :| [])]
      assertEq "foo.com script-src" header "script-src https://foo.com/bar%20%2A"
    yit "works with wildcard subdomains" $ do
      let header = getCspPolicy [ScriptSrc (Host (fromJust $ escapeAndParseURI "https://*.foo.com:443/x") :| [])]
      assertEq "wildcard subdomain" header "script-src https://*.foo.com:443/x"
      assertEq "wildcard only at host start" (show <$> escapeAndParseURI "https://foo.com/a://*.b") (Just "https://foo.com/a://%2A.b")
      assertEq "bare wildcard host stays escaped" (show <$> escapeAndParseURI "https://*") (Just "https://%2A")
      assertEq "wildcard in quasi-quoter" [csp|script-src https://*.foo.com|] [ScriptSrc (Host (fromJust $ escapeAndParseURI "https://*.foo.com") :| [])]
    yit "works with CSP Level 3 sources" $ do
      let header = getCspPolicy [ScriptSrc (Hash Sha256 "abc+/=" :| [UnsafeHashes, WasmUnsafeEval])]
      assertEq "level 3 sources" header "script-src 'sha256-abc+/=' 'unsafe-hashes' 'wasm-unsafe-eval'"
      assertEq "hash is filtered" (textSource (Hash Sha512 "x'; script-src *")) "'sha512-xscript-src'"
    yit "works with upgrade-insecure-requests and trusted types" $ do
      let header = getCspPolicy [UpgradeInsecureRequests, RequireTrustedTypesForScript, TrustedTypes ["foo", "'allow-duplicates'", "x; y"]]
      assertEq "trusted types" header "upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types foo 'allow-duplicates' xy"
      assertEq "no policies" (getCspPolicy [TrustedTypes []]) "trusted-types"
    yit "works with nonce-source" $ do
      let header = getCspPolicy [ScriptSrc (nonce "foo" :| [])]
      assertEq "basic nonce-source" header "script-src 'nonce-foo'"
    yit "works with report_uri" $ do
      let dom = fromJust $ escapeAndParseURI "https://foo.com"
          header = getCspPolicy [ReportUri dom]
      assertEq "report-uri" header "report-uri https://foo.com"
    yit "enforces wildcards" $ do
      let header = getCspPolicy [ScriptSrc (Wildcard :| [Https])]
      assertEq "* should be alone" header "script-src *"
    yit "enforces nones" $ do
      let header = getCspPolicy [ScriptSrc (None :| [Https])]
      assertEq "none should be alone" header "script-src 'none'"
    yit "works with plugin-types" $ do
      let dom = pure $ fromJust $ parseMIMEType "text/plain"
          header = getCspPolicy [PluginTypes dom]
      assertEq "plugin-types" header "plugin-types text/plain"
    yit "plugin-types drops params and cannot inject directives" $ do
      let evil = Type (Other "x" "y; script-src *\r\nX-Evil: injected") []
          withParams = fromJust $ parseMIMEType "text/plain; charset=utf-8"
          header = getCspPolicy [PluginTypes (evil :| [withParams])]
      assertEq "plugin-types" header "plugin-types x/yscript-srcX-Evilinjected text/plain"
    yit "works with base-uri" $ do
      let header = getCspPolicy [BaseUri (None :| [])]
      assertEq "base-uri" header "base-uri 'none'"
    yit "works with worker-src" $ do
      let header = getCspPolicy [WorkerSrc (Self :| [])]
      assertEq "worker-src" header "worker-src 'self'"
    yit "works with manifest-src" $ do
      let header = getCspPolicy [ManifestSrc (Self :| [])]
      assertEq "manifest-src" header "manifest-src 'self'"
    yit "works with prefetch-src" $ do
      let header = getCspPolicy [PrefetchSrc (Https :| [Self])]
      assertEq "prefetch-src" header "prefetch-src https: 'self'"
    yit "works with report-to" $ do
      let header = getCspPolicy [ReportTo "csp-endpoint"]
      assertEq "report-to" header "report-to csp-endpoint"
  ydescribe "Headers" $ do
    yit "get set" $ do
      get HomeR
      assertHeader "Content-Security-Policy" "script-src 'self'; style-src https: 'self'"
    yit "report-only" $ do
      get ReportOnlyR
      assertHeader "Content-Security-Policy-Report-Only" "script-src 'self'"
  ydescribe "Sandboxes" $ do
    yit "works when empty" $ do
      let header = getCspPolicy [Sandbox []]
      assertEq "empty sandbox" header "sandbox"
    yit "works when not empty" $ do
      let header = getCspPolicy [Sandbox [AllowForms, AllowScripts]]
      assertEq "empty sandbox" header "sandbox allow-forms allow-scripts"
  ydescribe "Parsing" $ do
    yit "works" $ do
      assertEq "*" (parseOnly source "*") (Right Wildcard)
      assertEq "nonce" (parseOnly source "'nonce-foo'") (Right $ nonce "foo")
      assertEq "none" (parseOnly source "'none'") (Right None)
      assertEq "self" (parseOnly source "'self'") (Right Self)
      assertEq "data:" (parseOnly source "data:") (Right DataScheme)
      assertEq "https://foo.com" (parseOnly source "https://foo.com") (Right $ Host (fromJust (escapeAndParseURI "https://foo.com")))
      assertEq "https:" (parseOnly source "https:") (Right Https)
      assertEq "unsafe-inline" (parseOnly source "unsafe-inline") (Right UnsafeInline)
      assertEq "unsafe-eval" (parseOnly source "unsafe-eval") (Right UnsafeEval)
      assertEq "default-src self data:" (parseOnly withSourceList "default-src 'self' data:") (Right $ DefaultSrc (Self :| [DataScheme]))
      assertEq "report-uri http://hello.com" (parseOnly reportUri "report-uri http://hello.com") (Right $ ReportUri (fromJust (escapeAndParseURI "http://hello.com")))
      assertEq "report-to csp-endpoint" (parseOnly reportTo "report-to csp-endpoint") (Right $ ReportTo "csp-endpoint")
      assertEq "worker-src self" (parseOnly withSourceList "worker-src 'self'") (Right $ WorkerSrc (Self :| []))
      assertEq "manifest-src self" (parseOnly withSourceList "manifest-src 'self'") (Right $ ManifestSrc (Self :| []))
      assertEq "prefetch-src self" (parseOnly withSourceList "prefetch-src 'self'") (Right $ PrefetchSrc (Self :| []))
      assertEq "base-uri self" [csp|base-uri 'self'|] [BaseUri (Self :| [])]
      assertEq "level 3 sources th" [csp|script-src 'sha384-ab+c=' 'unsafe-hashes' 'wasm-unsafe-eval'|] [ScriptSrc (Hash Sha384 "ab+c=" :| [UnsafeHashes, WasmUnsafeEval])]
      assertEq "level 3 directives th" [csp|upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types foo 'allow-duplicates'|] [UpgradeInsecureRequests, RequireTrustedTypesForScript, TrustedTypes ["foo", "'allow-duplicates'"]]
      assertEq "sandbox prefixes" (parseOnly sandbox "sandbox allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation allow-popups") (Right $ Sandbox [AllowPopupsToEscapeSandbox, AllowTopNavigationByUserActivation, AllowPopups])
      assertEq "sandbox allow-forms allow-scripts" (parseOnly sandbox "sandbox allow-forms allow-scripts") (Right $ Sandbox [AllowForms, AllowScripts])
    yit "works with lists" $ do
      let resultHttps = [ImgSrc $ Self :| [Https], ScriptSrc $ Host (fromJust $ escapeAndParseURI "https://foo.com") :| []]
      assertEq "scripts and images" (parseOnly directive "img-src 'self' https:; script-src https://foo.com") (Right resultHttps)
      let resultData = [ImgSrc $ Self :| [DataScheme, Host (fromJust $ escapeAndParseURI "https://foo.com")]]
      assertEq "data and hosts" (parseOnly directive "img-src 'self' data: https://foo.com") (Right resultData)
    yit "works with nonces and th" $ do
      let result = [ScriptSrc $ (nonce "foo") :| []]
      assertEq "nonces and th" [csp|script-src 'nonce-foo'|] result
    yit "works with dynamic nonces and th" $ do
      let n = "bar"
          result = [ScriptSrc $ (nonce "bar") :| []]
      assertEq "dynamic nonces and th" [csp|script-src $nonce-n|] result
    yit "works with th" $ do
      let result = [ImgSrc $ Self :| [Https], ScriptSrc $ Host (fromJust $ escapeAndParseURI "https://foo.com") :| []]
      assertEq "with th" [csp|img-src 'self' https:;  script-src https://foo.com|] result
      let url = fromJust $ escapeAndParseURI "https://foo.com"
      assertEq "with antiquoting" [csp|img-src 'self' https:; script-src $url|] result
    yit "works with th and newlines" $ do
      let attempt = [csp|
        default-src 'self'
      |]
      assertEq "with th and newlines" attempt [DefaultSrc (Self :| [])]

middlewareTest :: Spec
middlewareTest = yesodSpecApp Test getApp $ do
  ydescribe "Middleware" $ do
    yit "works" $ do
      get NoCspR
      assertHeader "Content-Security-Policy" "frame-ancestors 'self'"
      assertHeader "Content-Security-Policy-Report-Only" "upgrade-insecure-requests"
  where
    getApp = cspMiddleware [FrameAncestors (Self :| [])] . cspMiddlewareReportOnly [UpgradeInsecureRequests] <$>
             toWaiAppPlain Test
