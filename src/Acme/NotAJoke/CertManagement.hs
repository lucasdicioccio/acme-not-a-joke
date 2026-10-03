{- | A series of helper to work with Certificate Signing Requests and
certificates.

CSRs can be built with 'createCSR' from a key of
"Acme.NotAJoke.KeyManagement", or with the `openssl req` command and then
loaded with 'loadCSR'.
-}
module Acme.NotAJoke.CertManagement (
    -- * Create CSRs
    createCSR,
    createCSRWith,

    -- * Load and write CSRs
    loadDER,
    loadCSR,
    writeCSRDER,
    writeCSRPEM,
    csrFromDER,
    csrToDER,
    encodeCSRPEM,
    decodeCSRPEM,

    -- * Certificates
    certificateChain,
    decodeCertificateChain,
    encodeCertificateChain,
    loadCertificateChain,
    writeCertificateChain,
) where

import Acme.NotAJoke.Api.CSR
import qualified Acme.NotAJoke.Api.Certificate as Certificate
import Control.Lens (preview, review)
import qualified Crypto.JOSE.JWK as JWK
import Data.Bifunctor (bimap, first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Encoding

import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.BitArray (toBitArray)
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.Types
import qualified Data.PEM as PEM
import qualified Data.X509 as X509

{- | Creates a CSR for a list of DNS names, signed (RSA with SHA-256) with the
key of the certificate.

The names all are requested as subject alternative names, the first one also
is the common name of the subject (unless it is too long to fit in a common
name). Names should be the ones in the identifiers of the order, in ASCII
form (i.e., punycode-encoded for internationalized names).

The key must not be the account key.
-}
createCSR :: RSA.PrivateKey -> NonEmpty Text -> IO (Either String CSR)
createCSR key names
    | not (all validName names) = pure (Left "DNS names must be non-empty ASCII strings")
    | otherwise = createCSRWith key subject altNames
  where
    validName :: Text -> Bool
    validName name = not (Text.null name) && Text.all (\c -> c > ' ' && c < '\DEL') name

    commonName :: Text
    commonName = NonEmpty.head names

    -- the upper bound of a common name, see RFC-5280
    subject :: X509.DistinguishedName
    subject
        | Text.length commonName <= 64 =
            X509.DistinguishedName
                [ (getObjectID X509.DnCommonName, ASN1CharacterString UTF8 (Encoding.encodeUtf8 commonName))
                ]
        | otherwise = X509.DistinguishedName []

    altNames :: [X509.AltName]
    altNames = X509.AltNameDNS . Text.unpack <$> NonEmpty.toList names

{- | Creates a CSR for a given subject and a given list of subject alternative
names, signed (RSA with SHA-256) with the key of the certificate.

The subject may be empty, ACME servers typically only care about the subject
alternative names.
-}
createCSRWith :: RSA.PrivateKey -> X509.DistinguishedName -> [X509.AltName] -> IO (Either String CSR)
createCSRWith key subject altNames = do
    signed <- PKCS15.signSafer (Just SHA256) key (encodeASN1' DER requestInfo)
    pure $ bimap show (csrFromDER . encodeASN1' DER . request) signed
  where
    -- CertificationRequestInfo of RFC-2986
    requestInfo :: [ASN1]
    requestInfo =
        asn1Container Sequence $
            IntVal 0
                : toASN1 subject (toASN1 (X509.PubKeyRSA (RSA.private_pub key)) attributes)

    -- an extensionRequest attribute (RFC-2985) carries the alternative names
    attributes :: [ASN1]
    attributes =
        asn1Container (Container Context 0) $
            case altNames of
                [] -> []
                _ ->
                    asn1Container Sequence $
                        OID [1, 2, 840, 113549, 1, 9, 14]
                            : asn1Container Set (toASN1 extensions [])

    extensions :: X509.Extensions
    extensions =
        X509.Extensions $
            Just [X509.extensionEncode False (X509.ExtSubjectAltName altNames)]

    -- CertificationRequest of RFC-2986
    request :: ByteString -> [ASN1]
    request signature =
        asn1Container Sequence $
            requestInfo
                <> toASN1 (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA) []
                <> [BitString (toBitArray signature 0)]

-- | Wraps ASN.1 values in a container.
asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] <> l <> [End ty]

-- | Loads a DER file in base64 format.
loadDER :: FilePath -> IO Base64DER
loadDER =
    fmap (Base64DER . Encoding.decodeUtf8 . review JWK.base64url) . LBS.readFile

{- | Loads a CSR from a file, which is either a DER file or a PEM file (as
`openssl req -new` writes by default).
-}
loadCSR :: FilePath -> IO (Either String CSR)
loadCSR path = do
    bytes <- ByteString.readFile path
    pure $
        if "-----BEGIN" `ByteString.isInfixOf` bytes
            then decodeCSRPEM bytes
            else csrFromDER bytes <$ first show (decodeASN1' DER bytes)

-- | Writes a CSR to a DER file.
writeCSRDER :: CSR -> FilePath -> IO (Either String ())
writeCSRDER csr path = traverse (ByteString.writeFile path) (csrToDER csr)

-- | Writes a CSR to a PEM file.
writeCSRPEM :: CSR -> FilePath -> IO (Either String ())
writeCSRPEM csr path = traverse (ByteString.writeFile path) (encodeCSRPEM csr)

-- | Wraps the DER encoding of a CSR.
csrFromDER :: ByteString -> CSR
csrFromDER =
    CSR . Base64DER . Encoding.decodeUtf8 . review JWK.base64url

{- | Unwraps the DER encoding of a CSR.

Fails if the CSR does not hold base64url-encoded content.
-}
csrToDER :: CSR -> Either String ByteString
csrToDER (CSR (Base64DER txt)) =
    maybe (Left "invalid base64url content") Right $
        preview JWK.base64url (Encoding.encodeUtf8 txt)

-- | Encodes a CSR as a PEM file content.
encodeCSRPEM :: CSR -> Either String ByteString
encodeCSRPEM =
    fmap (PEM.pemWriteBS . PEM.PEM "CERTIFICATE REQUEST" []) . csrToDER

-- | Decodes the first CSR found in a PEM file content.
decodeCSRPEM :: ByteString -> Either String CSR
decodeCSRPEM bytes = do
    pems <- PEM.pemParseBS bytes
    case filter isCSR pems of
        [] -> Left "no certificate request in PEM content"
        (pem : _) -> Right (csrFromDER (PEM.pemContent pem))
  where
    isCSR pem = PEM.pemName pem `elem` ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"]

{- | Parses the certificates of the PEM returned by the ACME server.

The first certificate is the one for the names you ordered, followed by the
certificates of the issuers.
-}
certificateChain :: Certificate.PEM -> Either String [X509.SignedCertificate]
certificateChain (Certificate.PEM bytes) = decodeCertificateChain (LBS.toStrict bytes)

-- | Parses all the certificates found in a PEM file content.
decodeCertificateChain :: ByteString -> Either String [X509.SignedCertificate]
decodeCertificateChain bytes = do
    pems <- PEM.pemParseBS bytes
    traverse (X509.decodeSignedCertificate . PEM.pemContent) (filter isCertificate pems)
  where
    isCertificate pem = PEM.pemName pem == "CERTIFICATE"

-- | Encodes certificates as a PEM file content.
encodeCertificateChain :: [X509.SignedCertificate] -> ByteString
encodeCertificateChain =
    foldMap (PEM.pemWriteBS . PEM.PEM "CERTIFICATE" [] . X509.encodeSignedObject)

-- | Loads all the certificates of a PEM file.
loadCertificateChain :: FilePath -> IO (Either String [X509.SignedCertificate])
loadCertificateChain = fmap decodeCertificateChain . ByteString.readFile

{- | Writes certificates to a PEM file.

Useful to store the certificate apart from the ones of its issuers.
-}
writeCertificateChain :: [X509.SignedCertificate] -> FilePath -> IO ()
writeCertificateChain certs path = ByteString.writeFile path (encodeCertificateChain certs)
