{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}

import           Codec.MIME.Parse          (parseMIMEType)
import           Data.Attoparsec.Text
import qualified Data.ByteString.Lazy      as BL
import           Data.Text                 (Text)
import           Network.Wai.Test          (simpleBody)
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
/nonce NonceR GET
|]

instance Yesod Test

getHomeR :: Handler Html
getHomeR = do
  cspPolicy [ScriptSrc (Self :| []), StyleSrc (Https :| [Self])]
  defaultLayout [whamlet|hello|]

getNoCspR :: Handler Html
getNoCspR = do
  defaultLayout [whamlet|hello|]

-- Responds with the request's nonce, after checking it is stable within the request.
getNonceR :: Handler Text
getNonceR = do
  n <- getCspNonce
  n' <- getCspNonce
  cspPolicy [ScriptSrc (nonce n :| [])]
  return $ if n == n' then n else "nonce changed within the request"

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
    yit "escapes commas in domains" $ do
      let dom = fromJust $ escapeAndParseURI "https://foo.com,script-src"
          header = getCspPolicy [ScriptSrc (Host dom :| [])]
      assertEq "comma in host" header "script-src https://foo.com%2Cscript-src"
    yit "escapes commas in report-uri" $ do
      let dom = fromJust $ escapeAndParseURI "https://foo.com/a,b"
          header = getCspPolicy [ReportUri dom]
      assertEq "comma in report-uri" header "report-uri https://foo.com/a%2Cb"
    yit "works with nonce-source" $ do
      let header = getCspPolicy [ScriptSrc (nonce "foo" :| [])]
      assertEq "basic nonce-source" header "script-src 'nonce-foo'"
    yit "keeps base64 and base64url nonces intact" $ do
      let header = getCspPolicy [ScriptSrc (nonce "aB3+/9-_==" :| [])]
      assertEq "base64 nonce-source" header "script-src 'nonce-aB3+/9-_=='"
    yit "strips non-base64 characters from nonces" $ do
      let header = getCspPolicy [ScriptSrc (nonce "a,b\r\nX-Injected: yes; 'c'" :| [])]
      assertEq "nonce injection" header "script-src 'nonce-abX-Injectedyesc'"
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
    yit "prevents directive injection via report-to" $ do
      let header = getCspPolicy [DefaultSrc (Self :| []), ReportTo "g; script-src * 'unsafe-inline'"]
      assertEq "report-to injection" header "default-src 'self'; report-to gscript-src*'unsafe-inline'"
    yit "strips policy separators and line breaks from report-to" $ do
      let header = getCspPolicy [ReportTo "g,\r\nX-Injected: yes"]
      assertEq "report-to separators" header "report-to gX-Injectedyes"
  ydescribe "Headers" $
    yit "get set" $ do
      get HomeR
      assertHeader "Content-Security-Policy" "script-src 'self'; style-src https: 'self'"
  ydescribe "Nonces" $
    yit "are fresh per request and match the header" $ do
      let responseNonce = withResponse $ \r -> do
            let n = BL.toStrict (simpleBody r)
            assertEq "nonce length" 24 (BL.length (simpleBody r))
            assertHeader "Content-Security-Policy" ("script-src 'nonce-" <> n <> "'")
            return n
      get NonceR
      n1 <- responseNonce
      get NonceR
      n2 <- responseNonce
      assertNotEq "fresh nonce per request" n1 n2
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
  where
    getApp = cspMiddleware [FrameAncestors (Self :| [])] <$>
             toWaiAppPlain Test
