-- | A series of helper to work with Certificate Signing Requests.
--
-- See the `openssl req` command to build CSR and DER files.
module Acme.NotAJoke.CertManagement where

import qualified Data.Text.Encoding as Encoding
import qualified Data.ByteString.Lazy as LBS
import Control.Lens hiding ((.=))
import qualified Crypto.JOSE.JWK as JWK
import Acme.NotAJoke.Api.CSR

-- | Loads a DER file in base64 format.
loadDER :: FilePath -> IO Base64DER
loadDER =
  fmap (Base64DER . Encoding.decodeUtf8 . review JWK.base64url) . LBS.readFile
