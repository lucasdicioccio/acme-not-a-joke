{-# LANGUAGE DeriveGeneric #-}

-- | The @meta@ field of the directory of an ACME server (RFC-8555 section 7.1.1).
module Acme.NotAJoke.Api.Meta where

import Data.Aeson (FromJSON (..))
import Data.Text (Text)
import GHC.Generics (Generic)

import Acme.NotAJoke.Api.Endpoint (Url)

-- | A domain name that CAA records can use to designate the ACME server.
type CAAIdentity = Text

-- | RFC-defined ACME server metadata.
data Meta
    = Meta
    { caaIdentities :: [CAAIdentity]
    , termsOfService :: Url "TOS"
    , website :: Url "website"
    }
    deriving (Show, Generic)

instance FromJSON Meta
