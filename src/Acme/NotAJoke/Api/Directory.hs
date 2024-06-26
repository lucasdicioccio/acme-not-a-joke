{-# LANGUAGE DeriveGeneric #-}

module Acme.NotAJoke.Api.Directory where

import Control.Lens hiding ((.=))
import Data.Aeson (FromJSON (..))
import Data.Coerce (coerce)
import GHC.Generics (Generic)
import qualified Network.Wreq as Wreq

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

directory :: BaseUrl -> Endpoint "directory"
directory baseUrl = coerce $ baseUrl <> "directory"

-- | Fetches the server's directory.
fetchDirectory :: Endpoint "directory" -> IO Directory
fetchDirectory ep = do
    r <- Wreq.asJSON =<< get ep
    pure $ r ^. Wreq.responseBody
