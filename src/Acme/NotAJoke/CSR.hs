{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | A series of helper to work with Certificate Signing Requests.
--
-- See the `openssl req` command to build CSR and DER files.
module Acme.NotAJoke.CSR where

import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import qualified Data.ByteString.Lazy as LBS
import Data.Aeson (FromJSON(..), ToJSON(..))
import Control.Lens hiding ((.=))
import qualified Crypto.JOSE.JWK as JWK

newtype Base64DER = Base64DER Text
  deriving (Show, FromJSON, ToJSON)

newtype CSR = CSR Base64DER
  deriving (Show, FromJSON, ToJSON)

doLoadDER :: FilePath -> IO Base64DER
doLoadDER = fmap (Base64DER . Encoding.decodeUtf8 . review JWK.base64url) . LBS.readFile
