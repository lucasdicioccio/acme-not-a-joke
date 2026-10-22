{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{- | Certificate Signing Requests as the ACME API carries them. To create,
load or write them, see "Acme.NotAJoke.CertManagement".
-}
module Acme.NotAJoke.Api.CSR where

import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Text (Text)

-- | The base64url encoding (without padding) of some DER-encoded data.
newtype Base64DER = Base64DER Text
    deriving (Show, FromJSON, ToJSON)

{- | A Certificate Signing Request, as sent to finalize an order.

Build one with 'Acme.NotAJoke.CertManagement.createCSR', or load one with
'Acme.NotAJoke.CertManagement.loadCSR'.
-}
newtype CSR = CSR Base64DER
    deriving (Show, FromJSON, ToJSON)
