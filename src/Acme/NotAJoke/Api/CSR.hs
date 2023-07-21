{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Acme.NotAJoke.Api.CSR where

import Data.Text (Text)
import Data.Aeson (FromJSON(..), ToJSON(..))

newtype Base64DER = Base64DER Text
  deriving (Show, FromJSON, ToJSON)

newtype CSR = CSR Base64DER
  deriving (Show, FromJSON, ToJSON)
