{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Acme.NotAJoke.Endpoint where

import GHC.TypeLits
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.ByteString.Lazy (ByteString)
import qualified Data.Text as Text
import Data.Aeson (FromJSON(..), ToJSON(..), Value)
import qualified Network.Wreq as Wreq


newtype Endpoint (s :: Symbol) = Endpoint Text
  deriving (Show, FromJSON)

type RawEndpoint = Text

newtype Url (s :: Symbol) = Url Text
  deriving (Show, FromJSON, ToJSON)

type BaseUrl = Text

get :: Endpoint a -> IO (Wreq.Response ByteString)
get ep = Wreq.get (wrequrl ep)

raw :: Endpoint a -> RawEndpoint
raw = coerce

wrequrl :: Endpoint a -> String
wrequrl = Text.unpack . coerce

-- Problem

type Problem = Value

