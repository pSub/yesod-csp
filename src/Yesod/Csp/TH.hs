{-# LANGUAGE OverloadedStrings #-}

module Yesod.Csp.TH (
    source
    , withSourceList
    , reportUri
    , reportTo
    , pluginTypes
    , sandbox
    , sandboxOptions
    , directive
    , csp
  ) where

import           Codec.MIME.Parse          (parseMIMEType)
import           Control.Applicative
import           Data.Attoparsec.Text
import           Data.Generics
import           Data.List.NonEmpty        (NonEmpty (..))
import qualified Data.Text                 as T
import qualified Language.Haskell.TH       as TH
import           Language.Haskell.TH.Quote
import           Yesod.Csp

csp :: QuasiQuoter
csp = QuasiQuoter {
      quoteExp = \str -> do
        let c = parseOnly directive (T.pack str)
        case c of
          Left err -> error $ "csp parsing error: " ++ err -- compile time error
          Right x -> dataToExpQ (const Nothing `extQ` antiCsp) x
    , quotePat  = undefined
    , quoteType = undefined
    , quoteDec  = undefined
    }

antiCsp :: Source -> Maybe (TH.Q TH.Exp)
antiCsp (MetaSource x) = if T.isPrefixOf noncePrefix x
  then Just . return $ TH.AppE (TH.VarE (TH.mkName "nonce")) (TH.VarE (TH.mkName (T.unpack (nonceVar x))))
  else Just . return $ TH.AppE (TH.ConE (TH.mkName "Host")) (TH.VarE (TH.mkName (T.unpack x)))
  where noncePrefix = "nonce-"
        nonceVar = T.drop (T.length noncePrefix)
antiCsp _ = Nothing

metaSource :: Parser Source
metaSource = do
  _ <- char '$'
  x <- many (digit <|> letter <|> char '-')
  return $ MetaSource (T.pack x)

source :: Parser Source
source = wildcard
         <|> none
         <|> self
         <|> dataScheme
         <|> https
         <|> host
         <|> unsafeInline
         <|> unsafeEval
         <|> strictDynamic
         <|> parseNonce
         <|> metaSource
  where wildcard = string "*" *> pure Wildcard
        none = string "'none'" *> pure None
        self = string "'self'" *> pure Self
        dataScheme = string "data:" *> pure DataScheme
        parseNonce :: Parser Source
        parseNonce = do
          _ <- char '\''
          _ <- string "nonce"
          _ <- char '-'
          n <- takeTill (== '\'')
          _ <- char '\''
          return $ nonce n
        host :: Parser Source
        host = do
          u <- takeTill separated
          case escapeAndParseAnyURI u of
            Nothing -> fail "host"
            Just uri -> return $ Host uri
        https = do
          _ <- string "https:"
          c <- peekChar
          case c of
            (Just ' ') -> return Https
            (Just ';') -> return Https
            Nothing -> return Https
            _ -> fail "https"
        -- quoted is the standard CSP form; unquoted is kept for compatibility
        keyword k = string ("'" <> k <> "'") <|> string k
        unsafeInline = keyword "unsafe-inline" *> pure UnsafeInline
        unsafeEval = keyword "unsafe-eval" *> pure UnsafeEval
        strictDynamic = keyword "strict-dynamic" *> pure StrictDynamic

separated :: Char -> Bool
separated x = x == ';' || x == ' '

withSourceList :: Parser Directive
withSourceList = defaultSrc
                 <|> scriptSrc
                 <|> styleSrc
                 <|> imgSrc
                 <|> connectSrc
                 <|> fontSrc
                 <|> objectSrc
                 <|> mediaSrc
                 <|> frameSrc
                 <|> frameAncestors
                 <|> childSrc
                 <|> formAction
                 <|> workerSrc
                 <|> manifestSrc
                 <|> prefetchSrc
  where defaultSrc = d "default-src" DefaultSrc
        scriptSrc = d "script-src" ScriptSrc
        styleSrc = d "style-src" StyleSrc
        imgSrc = d "img-src" ImgSrc
        connectSrc = d "connect-src" ConnectSrc
        fontSrc = d "font-src" FontSrc
        objectSrc = d "object-src" ObjectSrc
        mediaSrc = d "media-src" MediaSrc
        frameSrc = d "frame-src" FrameSrc
        frameAncestors = d "frame-ancestors" FrameAncestors
        childSrc = d "child-src" ChildSrc
        formAction = d "form-action" FormAction
        workerSrc = d "worker-src" WorkerSrc
        manifestSrc = d "manifest-src" ManifestSrc
        prefetchSrc = d "prefetch-src" PrefetchSrc
        d x y = string x >> skipSpace >> y <$> slist
        slist = (:|) <$> source <*> many (char ' ' *> source)

reportUri :: Parser Directive
reportUri = do
  _ <- string "report-uri"
  skipSpace
  u <- takeTill separated
  case escapeAndParseAnyURI u of
    Nothing -> fail "reportUri" -- n.b. compile time error
    Just uri -> return $ ReportUri uri

reportTo :: Parser Directive
reportTo = do
  _ <- string "report-to"
  skipSpace
  g <- takeTill separated
  if T.null g
    then fail "reportTo" -- n.b. compile time error
    else return $ ReportTo g

baseUri :: Parser Directive
baseUri = do
  _ <- string "base-uri"
  skipSpace
  u <- takeTill separated
  case escapeAndParseAnyURI u of
    Nothing -> fail "baseUri" -- n.b. compile time error
    Just uri -> return $ BaseUri uri

pluginTypes :: Parser Directive
pluginTypes = do
  _ <- string "plugin-types"
  skipSpace
  u <- takeTill separated
  case parseMIMEType u of
    Nothing -> fail "plugin-types" -- n.b. compile time error
    Just mimeType -> return $ PluginTypes $ pure mimeType

sandbox :: Parser Directive
sandbox = do
  _ <- string "sandbox"
  skipSpace
  x <- sepBy sandboxOptions skipSpace
  return $ Sandbox x

sandboxOptions :: Parser SandboxOptions
sandboxOptions = allowForms
                 <|> allowScripts
                 <|> allowSameOrigin
                 <|> allowTopNavigation
  where allowForms = string "allow-forms" *> pure AllowForms
        allowScripts = string "allow-scripts" *> pure AllowScripts
        allowSameOrigin = string "allow-same-origin" *> pure AllowSameOrigin
        allowTopNavigation = string "allow-top-navigation" *> pure AllowTopNavigation

separator :: Parser ()
separator = char ';' *> skipSpace

directive :: Parser DirectiveList
directive = sepBy (skipSpace *> d) separator <* (skipSpace *> endOfInput)
  where d = withSourceList <|> reportUri <|> reportTo <|> baseUri <|> pluginTypes <|> sandbox
