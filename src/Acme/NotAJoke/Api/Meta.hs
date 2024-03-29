{-# LANGUAGE DeriveGeneric #-}
module Acme.NotAJoke.Api.Meta where

import GHC.Generics (Generic)
import Data.Text (Text)
import Data.Aeson (FromJSON(..))

import Acme.NotAJoke.Api.Endpoint (Url)

type CAAIdentity = Text

-- | RFC-defined ACME server metadata.
data Meta
  = Meta
  { caaIdentities :: [ CAAIdentity ]
  , termsOfService :: Url "TOS"
  , website :: Url "website"
  } deriving (Show, Generic)
instance FromJSON Meta
