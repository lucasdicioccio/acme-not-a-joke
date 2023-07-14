{-# LANGUAGE DeriveGeneric #-}
module Acme.NotAJoke.Directory where

import GHC.Generics (Generic)
import Data.Coerce (coerce)
import Data.Aeson (FromJSON(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Meta

-- | RFC-defined directory structure.
-- 
-- Mainly contains a series of endpoints.
data Directory
  = Directory
  { meta :: Meta
  , newNonce :: Endpoint "newNonce"
  , newAccount :: Endpoint "newAccount"
  , newOrder :: Endpoint "newOrder" 
  , keyChange :: Endpoint "keyChange"
  , renewalInfo :: Endpoint "renewalInfo"
  , revokeCert :: Endpoint "revokeCert"
  } deriving (Show, Generic)
instance FromJSON Directory

directory :: BaseUrl -> Endpoint "directory"
directory baseUrl = coerce $ baseUrl <> "directory"

-- | Fetches the server's directory.
fetchDirectory :: Endpoint "directory" -> IO Directory
fetchDirectory ep = do
  r <- Wreq.asJSON =<< get ep
  pure $ r ^. Wreq.responseBody

