{- | Certificate revocation (RFC-8555 section 7.6).

A revocation request carries the DER encoding of the certificate to revoke
and, optionally, a reason. It is sent to the 'revokeCert' endpoint of the
'Acme.NotAJoke.Api.Directory.Directory', signed either:

* with the account key, using the KID of the account which ordered the
  certificate (or of an account holding authorizations for all its names),
  see 'postRevokeCertificate'
* with the key of the certificate itself (the key which signed the CSR, see
  'Acme.NotAJoke.KeyManagement.jwkFromRSAKey'), which needs no account and is
  the way out when the account key is lost, see
  'postRevokeCertificateWithCertKey'

The server replies with an empty 200 response when the certificate is
revoked; an already revoked certificate is rejected with an
@urn:ietf:params:acme:error:alreadyRevoked@ problem (see 'readProblem').
-}
module Acme.NotAJoke.Api.Revocation where

import Control.Lens (review)
import Data.Aeson (encode, object, (.=))
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text.Encoding as Encoding

import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.JWS as JWS
import qualified Data.X509 as X509

import Acme.NotAJoke.Api.CSR (Base64DER (..))
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Nonce

{- | Revocation reasons, from the CRLReason of RFC-5280 section 5.3.1.

ACME servers may accept only some of them: Let's Encrypt, for instance,
refuses 'CACompromise', 'CertificateHold', 'RemoveFromCRL' and 'AACompromise'.
-}
data RevocationReason
    = Unspecified
    | KeyCompromise
    | CACompromise
    | AffiliationChanged
    | Superseded
    | CessationOfOperation
    | CertificateHold
    | RemoveFromCRL
    | PrivilegeWithdrawn
    | AACompromise
    deriving (Show, Eq, Ord, Enum, Bounded)

-- | The code of a reason, as sent to the ACME server (7 is not used).
revocationReasonCode :: RevocationReason -> Int
revocationReasonCode reason =
    case reason of
        Unspecified -> 0
        KeyCompromise -> 1
        CACompromise -> 2
        AffiliationChanged -> 3
        Superseded -> 4
        CessationOfOperation -> 5
        CertificateHold -> 6
        RemoveFromCRL -> 8
        PrivilegeWithdrawn -> 9
        AACompromise -> 10

-- | A revocation request.
data Revocation
    = Revocation
    { revokedCertificate :: Base64DER
    -- ^ the certificate to revoke, DER-encoded in base64url
    , revocationReason :: Maybe RevocationReason
    -- ^ why the certificate is revoked, servers assume 'Unspecified' if missing
    }
    deriving (Show)

{- | A revocation request for a certificate (e.g., the first one of
'Acme.NotAJoke.CertManagement.certificateChain').
-}
revocation :: Maybe RevocationReason -> X509.SignedCertificate -> Revocation
revocation why = revocationDER why . X509.encodeSignedObject

-- | A revocation request for the DER encoding of a certificate.
revocationDER :: Maybe RevocationReason -> ByteString -> Revocation
revocationDER why der =
    Revocation (Base64DER $ Encoding.decodeUtf8 $ review JWK.base64url der) why

-- | The JSON payload of a revocation request.
serializeRevocation :: Revocation -> LBS.ByteString
serializeRevocation rev =
    encode $
        object $
            ("certificate" .= rev.revokedCertificate)
                : maybe [] (\r -> ["reason" .= revocationReasonCode r]) rev.revocationReason

-- | The (empty) response of a successful revocation.
newtype CertificateRevoked = CertificateRevoked Response
    deriving (Show)

{- | Revokes a certificate, signing the request with the account key and
the KID of the account.
-}
postRevokeCertificate :: JWS.JWK -> KID -> Endpoint "revokeCert" -> Nonce -> Revocation -> IO (Either AcmeError CertificateRevoked)
postRevokeCertificate jwk kid ep nonce rev =
    sendRevocation ep =<< kidSign jwk ep kid nonce (serializeRevocation rev)

{- | Revokes a certificate, signing the request with the key of the
certificate (as a JWK, see 'Acme.NotAJoke.KeyManagement.jwkFromRSAKey').

No account is needed: the JWS carries the public key, which the server
compares with the one of the certificate.
-}
postRevokeCertificateWithCertKey :: JWS.JWK -> Endpoint "revokeCert" -> Nonce -> Revocation -> IO (Either AcmeError CertificateRevoked)
postRevokeCertificateWithCertKey certJwk ep nonce rev =
    sendRevocation ep =<< jwkSign certJwk ep nonce (serializeRevocation rev)

sendRevocation :: Endpoint "revokeCert" -> Either JWS.Error (JWS.FlattenedJWS AcmeHeader) -> IO (Either AcmeError CertificateRevoked)
sendRevocation ep ebody =
    case ebody of
        Right body -> fmap CertificateRevoked <$> postJose ep (encode body)
        Left err -> pure $ Left $ SigningFailed err
