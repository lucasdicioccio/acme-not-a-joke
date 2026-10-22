{-# LANGUAGE DeriveGeneric #-}

{- | The directory of an ACME server (RFC-8555 section 7.1.1): the first thing
a client fetches, which lists the URLs of the other endpoints.

Only the directory URL is configured: it is 'directory' applied to the base
URL of the server (see "Acme.NotAJoke.LetsEncrypt").
-}
module Acme.NotAJoke.Api.Directory where

import Data.Aeson (FromJSON (..), eitherDecode)
import Data.Coerce (coerce)
import qualified Data.Text as Text
import GHC.Generics (Generic)
import qualified Network.HTTP.Client as HTTP

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Meta

{- | RFC-defined directory structure.

Mainly contains a series of endpoints.
-}
data Directory
    = Directory
    { meta :: Meta
    , newNonce :: Endpoint "newNonce"
    , newAccount :: Endpoint "newAccount"
    , newOrder :: Endpoint "newOrder"
    , keyChange :: Endpoint "keyChange"
    , renewalInfo :: Endpoint "renewalInfo"
    , revokeCert :: Endpoint "revokeCert"
    }
    deriving (Show, Generic)

instance FromJSON Directory

-- | The directory endpoint of a server, given its base URL (which ends with a @/@).
directory :: BaseUrl -> Endpoint "directory"
directory baseUrl = coerce $ baseUrl <> "directory"

-- | Fetches the server's directory.
fetchDirectory :: Endpoint "directory" -> IO (Either AcmeError Directory)
fetchDirectory ep = do
    r <- get ep
    pure $ readDirectory =<< r
  where
    readDirectory rsp =
        case eitherDecode (HTTP.responseBody rsp) of
            Right dir -> Right dir
            Left err -> Left $ UnexpectedResponse (Text.pack err) rsp
