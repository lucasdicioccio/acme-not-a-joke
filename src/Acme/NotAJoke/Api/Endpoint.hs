{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Acme.NotAJoke.Api.Endpoint where

import Data.Aeson (FromJSON (..), ToJSON (..), Value (..), decode)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as Strict
import Data.ByteString.Lazy (ByteString)
import Data.Coerce (coerce)
import Data.Text (Text)
import qualified Data.Text as Text
import GHC.TypeLits
import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Client.TLS as TLS
import Network.HTTP.Types.Header (Header, HeaderName)
import Network.HTTP.Types.Method (Method)
import Network.HTTP.Types.Status (statusIsSuccessful)

import qualified Crypto.JOSE.Error as JOSE

{- | A newtype helper to introduce unambiguous URL.
This newtype helps following the logical flow of ACME's dance.
-}
newtype Endpoint (purpose :: Symbol) = Endpoint Text
    deriving (Show, FromJSON)

-- | An undtyped URL.
type RawEndpoint = Text

{- | Same ad Endpoint but for full URLs (e.g., certificates have URLs but the
ACME server has normalized endpoints).
-}
newtype Url (purpose :: Symbol) = Url Text
    deriving (Show, FromJSON, ToJSON)

type BaseUrl = Text

raw :: Endpoint a -> RawEndpoint
raw = coerce

-- | An HTTP response from the ACME server, with its whole body.
type Response = HTTP.Response ByteString

{- | Problem object for rich errors.
The ACME RFCs uses the Problem RFC https://datatracker.ietf.org/doc/html/rfc7807 however we keep the object as an opaque Value as this library treat any error as an opaque error.
-}
type Problem = Value

{- | The "type" of a Problem (e.g., `urn:ietf:params:acme:error:badNonce`).
See https://datatracker.ietf.org/doc/html/rfc8555#section-6.7 for the ACME ones.
-}
problemType :: Problem -> Maybe Text
problemType = problemText "type"

-- | The human-readable "detail" of a Problem.
problemDetail :: Problem -> Maybe Text
problemDetail = problemText "detail"

problemText :: Text -> Problem -> Maybe Text
problemText key (Object o) =
    case KeyMap.lookup (Key.fromText key) o of
        Just (String txt) -> Just txt
        _ -> Nothing
problemText _ _ = Nothing

{- | What can go wrong in an ACME API call.

Network-level failures (no connection, TLS errors, invalid URLs) are not
covered here: they still are raised as 'HTTP.HttpException'.
-}
data AcmeError
    = -- | we could not sign the request, nothing has been sent
      SigningFailed JOSE.Error
    | -- | the server replied with a non-2xx status, see 'readProblem'
      ServerRejected Response
    | -- | the server replied with a 2xx status but we could not read what we were looking for
      UnexpectedResponse Text Response
    deriving (Show)

-- | Lookup the response of a server in an error (if any).
errorResponse :: AcmeError -> Maybe Response
errorResponse (SigningFailed _) = Nothing
errorResponse (ServerRejected rsp) = Just rsp
errorResponse (UnexpectedResponse _ rsp) = Just rsp

-- | Lookup the Problem document that ACME servers attach to their errors.
readProblem :: AcmeError -> Maybe Problem
readProblem (ServerRejected rsp) = decode $ HTTP.responseBody rsp
readProblem _ = Nothing

-- | Lookup a response header.
responseHeader :: HeaderName -> Response -> Maybe Strict.ByteString
responseHeader name rsp = lookup name (HTTP.responseHeaders rsp)

-- | Sorts out responses between successes and server errors.
checkResponse :: Response -> Either AcmeError Response
checkResponse rsp
    | statusIsSuccessful (HTTP.responseStatus rsp) = Right rsp
    | otherwise = Left (ServerRejected rsp)

{- | Performs an HTTP call.
Unlike a number of HTTP-libraries defaults, non-2xx responses are returned (as a 'ServerRejected') rather than thrown.
-}
call :: Method -> [Header] -> Endpoint a -> ByteString -> IO (Either AcmeError Response)
call method headers ep body = do
    manager <- TLS.getGlobalManager
    req <- HTTP.parseRequest (Text.unpack $ raw ep)
    let req' =
            req
                { HTTP.method = method
                , HTTP.requestHeaders = ("User-Agent", "haskell acme-not-a-joke") : headers
                , HTTP.requestBody = HTTP.RequestBodyLBS body
                }
    checkResponse <$> HTTP.httpLbs req' manager

get :: Endpoint a -> IO (Either AcmeError Response)
get ep = call "GET" [] ep ""

head_ :: Endpoint a -> IO (Either AcmeError Response)
head_ ep = call "HEAD" [] ep ""

-- | Posts a (serialized) JWS object.
postJose :: Endpoint a -> ByteString -> IO (Either AcmeError Response)
postJose = postJoseWith []

-- | Same as postJose but with extra headers.
postJoseWith :: [Header] -> Endpoint a -> ByteString -> IO (Either AcmeError Response)
postJoseWith headers = call "POST" (("Content-Type", "application/jose+json") : headers)
