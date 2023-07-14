-- | Helper to build a ValidationProof out of some token
module Acme.NotAJoke.Validation where

import Data.Coerce (coerce)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Control.Lens hiding ((.=))

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Challenge

-- | RFC-defined key authorizations.
newtype KeyAuthorization = KeyAuthorization Text
  deriving (Eq, Ord)

keyAuthorization :: Token -> JWK.JWK -> KeyAuthorization
keyAuthorization tok jwk =
    KeyAuthorization txt
  where
    txt,tok',b64thumbprint :: Text
    txt = tok' <> "." <> b64thumbprint
    tok' = coerce tok
    b64thumbprint = Encoding.decodeUtf8 $ review (JWK.base64url . JWK.digest) tprint

    tprint :: JWK.Digest JWK.SHA256
    tprint = view JWK.thumbprint jwk

newtype ValidationProof = ValidationProof Text
  deriving (Eq)

sha256digest :: KeyAuthorization -> ValidationProof
sha256digest (KeyAuthorization kauth) =
  ValidationProof
    $ Encoding.decodeUtf8 
    $ review (JWK.base64url . JWK.digest)
    hash
  where
    hash :: JWK.Digest JWK.SHA256
    hash = JWK.hash $ Encoding.encodeUtf8 kauth
