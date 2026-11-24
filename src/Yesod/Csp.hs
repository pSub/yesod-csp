{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}
-- | Add <http://content-security-policy.com/ CSP> headers to Yesod apps.
-- This helps reduce the risk of exposure to XSS and bad assets.
module Yesod.Csp (
  cspPolicy
  , cspPolicyReportOnly
  , getCspPolicy
  , cspMiddleware
  , cspMiddlewareReportOnly
  , EscapedURI
  , escapeAndParseURI
  , escapedTextForNonce
  , nonce
  , DirectiveList
  , Directive(..)
  , SourceList
  , Source(..)
  , HashAlgorithm(..)
  , SandboxOptions(..)
  , textSource
  ) where

import           Codec.MIME.Type as Mime
import           Control.Applicative ((<|>))
import           Control.Monad      (guard)
import qualified Data.CaseInsensitive as CI
import           Data.Char          (isAlphaNum, isAscii)
import           Data.Data          (Data)
import           Data.List.NonEmpty
import           Data.Text          (Text)
import qualified Data.Text          as T
import qualified Data.Text.Encoding as TE
import           Data.Typeable      (Typeable)
import           Network.URI
import           Yesod.Core
import           Network.Wai        (Middleware, mapResponseHeaders,
                                     modifyResponse)

-- | Adds a "Content-Security-Policy" header to your response.
--
-- > getExample1R :: Handler Html
-- > getExample1R = do
-- >   -- only allow scripts from my website
-- >   cspPolicy [ScriptSrc (Self :| [])]
-- >   defaultLayout $ do
-- >     addScriptRemote "http://httpbin.org/i_am_external"
-- >     [whamlet|hello|]
--
cspPolicy :: (MonadHandler m) => DirectiveList -> m ()
cspPolicy = addHeader cspHeaderName . directiveListToHeader

-- | Like 'cspPolicy', but adds a "Content-Security-Policy-Report-Only" header:
-- violations are only reported, not blocked.
cspPolicyReportOnly :: (MonadHandler m) => DirectiveList -> m ()
cspPolicyReportOnly = addHeader cspReportOnlyHeaderName . directiveListToHeader

cspHeaderName, cspReportOnlyHeaderName :: Text
cspHeaderName = "Content-Security-Policy"
cspReportOnlyHeaderName = "Content-Security-Policy-Report-Only"

-- | Returns a generated Content-Security-Policy header.
getCspPolicy :: DirectiveList -> Text
getCspPolicy = directiveListToHeader

-- | Creates a WAI 'Middleware' to add a Content-Security-Policy
-- header to every response.
cspMiddleware :: DirectiveList -> Middleware
cspMiddleware = headerMiddleware cspHeaderName

-- | Like 'cspMiddleware', but adds a "Content-Security-Policy-Report-Only" header.
cspMiddlewareReportOnly :: DirectiveList -> Middleware
cspMiddlewareReportOnly = headerMiddleware cspReportOnlyHeaderName

headerMiddleware :: Text -> DirectiveList -> Middleware
headerMiddleware name = addHeaderMiddleware . mkHeader . directiveListToHeader
  where
    addHeaderMiddleware = modifyResponse . mapResponseHeaders . insertAt 5
    mkHeader dltext = (CI.mk $ TE.encodeUtf8 name, TE.encodeUtf8 dltext)

insertAt :: Int -> a -> [a] -> [a]
insertAt n x xs =
  let (h, t) = Prelude.splitAt n xs
  in h ++ x : t

-- | A URI that is safe to put into a CSP header. Build it with 'escapeAndParseURI'.
--
-- The 'Data' instances of this type and of nonces exist only so the @csp@
-- quasi-quoter can lift policies. Generic traversals (e.g. SYB's @everywhere@)
-- can rewrite the strings inside them without escaping, so do not run them
-- over a 'DirectiveList'.
newtype EscapedURI = EscapedURI { uri :: URI } deriving (Eq, Data, Typeable)

newtype EscapedText = EscapedText { text :: String } deriving (Eq, Data, Typeable)

instance Show EscapedURI where
  show x = show (uri x)

instance Show EscapedText where
  show x = mconcat ["'nonce-", text x, "'"]

toEscape :: String
toEscape = ";'* "

notEscapable :: Char -> Bool
notEscapable = not . flip elem toEscape

-- | Escapes ';' '\'' '*' and ' ', and parses to URI.
-- A leading @*.@ in the host is kept as a wildcard subdomain, e.g. @https://*.example.com@.
escapeAndParseURI :: Text -> Maybe EscapedURI
escapeAndParseURI t = fmap EscapedURI (wildcardHost <|> parse t)
  where parse = parseURI . escapeURIString notEscapable . T.unpack
        wildcardHost = do
          let (s, r) = T.breakOn "://*." t
          u <- parse (s <> "://" <> T.drop 5 r)
          a <- uriAuthority u
          -- the "://*." must directly follow the scheme, not appear later in the URI
          guard (uriScheme u == T.unpack s ++ ":" && not (null (uriRegName a)))
          return u { uriAuthority = Just a { uriRegName = "*." ++ uriRegName a } }

-- | Escapes Text to be a valid nonce value
escapedTextForNonce :: String -> EscapedText
escapedTextForNonce = EscapedText . Prelude.filter notEscapable

-- | Escapes a Text value, returning a valid Nonce
nonce :: Text -> Source
nonce = Nonce . escapedTextForNonce . T.unpack

directiveListToHeader :: DirectiveList -> Text
directiveListToHeader = T.intercalate "; " . fmap textDirective

w :: Text -> SourceList -> Text
w = wrap

wrap :: Text -> SourceList -> Text
wrap k x = mconcat [k, " ", textSourceList x]

textSourceList :: SourceList -> Text
textSourceList = T.unwords . toList . filtered
  where filtered = fmap textSource . filterOut

-- * and none should be alone if present
filterOut :: SourceList -> SourceList
filterOut x | Wildcard `elem` x = Wildcard :| []
filterOut x | None `elem` x = None :| []
            | otherwise = x

-- | Represents a location from which assets may be loaded.
data Source = Wildcard
              | None
              | Self
              | DataScheme
              | Host EscapedURI
              | Https
              | UnsafeInline
              | UnsafeEval
              | StrictDynamic
              | UnsafeHashes
              | WasmUnsafeEval
              | Nonce EscapedText
              -- | A base64 hash of an allowed inline script or style.
              | Hash HashAlgorithm Text
              | MetaSource Text deriving (Eq, Show, Data, Typeable)

-- | Algorithm of a 'Hash' source.
data HashAlgorithm = Sha256 | Sha384 | Sha512 deriving (Eq, Show, Data, Typeable)

-- | A list of allowed sources for a directive.
type SourceList = NonEmpty Source

textSource :: Source -> Text
textSource Wildcard = "*"
textSource None = "'none'"
textSource Self = "'self'"
textSource DataScheme = "data:"
textSource (Host x) = (T.pack . show) x
textSource Https = "https:"
textSource UnsafeInline = "'unsafe-inline'"
textSource UnsafeEval = "'unsafe-eval'"
textSource StrictDynamic = "'strict-dynamic'"
textSource UnsafeHashes = "'unsafe-hashes'"
textSource WasmUnsafeEval = "'wasm-unsafe-eval'"
textSource (Hash a h) = mconcat ["'", alg a, "-", T.filter isBase64Char h, "'"]
  where alg Sha256 = "sha256"
        alg Sha384 = "sha384"
        alg Sha512 = "sha512"
        -- filtered on render, so no hash value can inject quotes or directives
        isBase64Char c = isAscii c && (isAlphaNum c || c `elem` ("+/=-_" :: String))
textSource (MetaSource _) = ""
textSource (Nonce x) = (T.pack . show) x

deriving instance Data Multipart
deriving instance Data Mime.MIMEType
deriving instance Data Mime.MIMEParam
deriving instance Data Mime.Type
type MimeTypeList = NonEmpty Mime.Type

-- | A list of restrictions to apply.
type DirectiveList = [Directive]

-- | A restriction on how assets can be loaded.
-- For example @ImgSrc@ concerns where images may be loaded from.
data Directive = DefaultSrc SourceList
                 | ScriptSrc SourceList
                 | StyleSrc SourceList
                 | ImgSrc SourceList
                 | ConnectSrc SourceList
                 | FontSrc SourceList
                 | ObjectSrc SourceList
                 | MediaSrc SourceList
                 | FrameSrc SourceList
                 -- | Applies a sandbox to the result. <http://content-security-policy.com/ See here> for more info.
                 | Sandbox [SandboxOptions]
                 | ReportUri EscapedURI
                 -- | CSP level 2 directives
                 | FrameAncestors SourceList
                 | ChildSrc SourceList
                 | FormAction SourceList
                 | BaseUri SourceList
                 | PluginTypes MimeTypeList
                 -- | CSP level 3 directives
                 | WorkerSrc SourceList
                 | ManifestSrc SourceList
                 | PrefetchSrc SourceList
                 -- | Names a reporting group defined by the @Reporting-Endpoints@ (or @Report-To@) response header.
                 | ReportTo Text
                 | UpgradeInsecureRequests
                 -- | @require-trusted-types-for 'script'@
                 | RequireTrustedTypesForScript
                 -- | Allowed Trusted Types policy names, e.g. @[\"myPolicy\", \"'allow-duplicates'\"]@.
                 | TrustedTypes [Text]
                 deriving (Eq, Show, Data, Typeable)


-- | Configuration options for the sandbox.
data SandboxOptions = AllowForms
                      | AllowScripts
                      | AllowSameOrigin
                      | AllowTopNavigation
                      | AllowDownloads
                      | AllowModals
                      | AllowOrientationLock
                      | AllowPointerLock
                      | AllowPopups
                      | AllowPopupsToEscapeSandbox
                      | AllowPresentation
                      | AllowStorageAccessByUserActivation
                      | AllowTopNavigationByUserActivation
                      | AllowTopNavigationToCustomProtocols deriving (Eq, Show, Data, Typeable)

textDirective :: Directive -> Text
textDirective (DefaultSrc x) = w "default-src" x
textDirective (ScriptSrc x) =  w "script-src" x
textDirective (StyleSrc x) =  w "style-src" x
textDirective (ImgSrc x) =  w "img-src" x
textDirective (ConnectSrc x) =  w "connect-src" x
textDirective (FontSrc x) =  w "font-src" x
textDirective (ObjectSrc x) =  w "object-src" x
textDirective (MediaSrc x) =  w "media-src" x
textDirective (FrameSrc x) =  w "frame-src" x
textDirective (ReportUri t) = mconcat ["report-uri ", (T.pack . show) t]
textDirective (Sandbox []) = "sandbox"
textDirective (Sandbox s) = mconcat ["sandbox ", T.unwords . fmap textSandbox $ s]
  where textSandbox AllowForms = "allow-forms"
        textSandbox AllowScripts = "allow-scripts"
        textSandbox AllowSameOrigin = "allow-same-origin"
        textSandbox AllowTopNavigation = "allow-top-navigation"
        textSandbox AllowDownloads = "allow-downloads"
        textSandbox AllowModals = "allow-modals"
        textSandbox AllowOrientationLock = "allow-orientation-lock"
        textSandbox AllowPointerLock = "allow-pointer-lock"
        textSandbox AllowPopups = "allow-popups"
        textSandbox AllowPopupsToEscapeSandbox = "allow-popups-to-escape-sandbox"
        textSandbox AllowPresentation = "allow-presentation"
        textSandbox AllowStorageAccessByUserActivation = "allow-storage-access-by-user-activation"
        textSandbox AllowTopNavigationByUserActivation = "allow-top-navigation-by-user-activation"
        textSandbox AllowTopNavigationToCustomProtocols = "allow-top-navigation-to-custom-protocols"
textDirective (FrameAncestors x) =  w "frame-ancestors" x
textDirective (ChildSrc x) = w "child-src" x
textDirective (FormAction x) = w "form-action" x
textDirective (BaseUri x) = w "base-uri" x
textDirective (PluginTypes t) = mconcat ["plugin-types ", (T.unwords . fmap textMimeType . toList) t]
  -- only type/subtype, restricted to RFC 6838 name chars, so ';', spaces and CR/LF cannot inject directives
  where textMimeType = T.filter isMimeChar . Mime.showMIMEType . Mime.mimeType
        isMimeChar c = isAscii c && (isAlphaNum c || c `elem` ("!#$&-^_.+/" :: String))
textDirective (WorkerSrc x) = w "worker-src" x
textDirective (ManifestSrc x) = w "manifest-src" x
textDirective (PrefetchSrc x) = w "prefetch-src" x
textDirective (ReportTo t) = mconcat ["report-to ", t]
textDirective UpgradeInsecureRequests = "upgrade-insecure-requests"
textDirective RequireTrustedTypesForScript = "require-trusted-types-for 'script'"
textDirective (TrustedTypes []) = "trusted-types"
textDirective (TrustedTypes ns) = T.unwords ("trusted-types" : fmap (T.filter isPolicyChar) ns)
  -- policy-name chars plus '*' and quotes for keywords; no ';', ',' or whitespace
  where isPolicyChar c = isAscii c && (isAlphaNum c || c `elem` ("-#=_/@.%*'" :: String))