{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Acme.NotAJoke.Endpoint where

import GHC.TypeLits
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.ByteString.Lazy (ByteString)
import qualified Data.Text as Text
import Data.Aeson (FromJSON(..), ToJSON(..), Value)
import qualified Network.Wreq as Wreq

-- | A newtype helper to introduce unambiguous URL.
-- This newtype helps following the logical flow of ACME's dance.
newtype Endpoint (purpose :: Symbol) = Endpoint Text
  deriving (Show, FromJSON)

-- | An undtyped URL.
type RawEndpoint = Text

-- | Same ad Endpoint but for full URLs (e.g., certificates have URLs but the
-- ACME server has normalized endpoints).
newtype Url (purpose :: Symbol) = Url Text
  deriving (Show, FromJSON, ToJSON)

type BaseUrl = Text

get :: Endpoint a -> IO (Wreq.Response ByteString)
get ep = Wreq.get (wrequrl ep)

raw :: Endpoint a -> RawEndpoint
raw = coerce

wrequrl :: Endpoint a -> String
wrequrl = Text.unpack . coerce

-- | Problem object for rich errors.
-- The ACME RFCs uses the Problem RFC https://datatracker.ietf.org/doc/html/rfc7807 however we keep the object as an opaque Value as this library treat any error as an opaque error.
type Problem = Value
