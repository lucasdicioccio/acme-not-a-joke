{- | Helpers to build the proofs that answer challenges (RFC-8555 section 8.1).

A challenge gives a 'Token'. The key authorization ('keyAuthorization') is
that token followed by the thumbprint of the account key, and what is
published depends on the challenge:

* HTTP-01: the key authorization itself, served at
  @http:\/\/{domain}\/.well-known\/acme-challenge\/{token}@
* DNS-01: its SHA-256 digest, base64url-encoded ('sha256digest'), in a TXT
  record at @_acme-challenge.{domain}@
* TLS-ALPN-01: its SHA-256 digest, in a certificate (see
  'Acme.NotAJoke.CertManagement.createTLSALPN01Certificate')
-}
module Acme.NotAJoke.Api.Validation where

import Control.Lens hiding ((.=))
import Data.Coerce (coerce)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Api.Challenge

-- | RFC-defined key authorizations.
newtype KeyAuthorization = KeyAuthorization Text
    deriving (Eq, Ord)

-- | Computes the key authorization of a challenge token for an account key.
keyAuthorization :: Token -> JWK.JWK -> KeyAuthorization
keyAuthorization tok jwk =
    KeyAuthorization txt
  where
    txt, tok', b64thumbprint :: Text
    txt = tok' <> "." <> b64thumbprint
    tok' = coerce tok
    b64thumbprint = Encoding.decodeUtf8 $ review (JWK.base64url . JWK.digest) tprint

    tprint :: JWK.Digest JWK.SHA256
    tprint = view JWK.thumbprint jwk

-- | The value to publish in the TXT record of a DNS-01 challenge.
newtype ValidationProof = ValidationProof Text
    deriving (Eq)

-- | The base64url-encoded SHA-256 digest of a key authorization.
sha256digest :: KeyAuthorization -> ValidationProof
sha256digest (KeyAuthorization kauth) =
    ValidationProof $
        Encoding.decodeUtf8 $
            review
                (JWK.base64url . JWK.digest)
                hash
  where
    hash :: JWK.Digest JWK.SHA256
    hash = JWK.hash $ Encoding.encodeUtf8 kauth
