{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Acme.NotAJoke.Api.CSR where

import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Text (Text)

newtype Base64DER = Base64DER Text
    deriving (Show, FromJSON, ToJSON)

newtype CSR = CSR Base64DER
    deriving (Show, FromJSON, ToJSON)
