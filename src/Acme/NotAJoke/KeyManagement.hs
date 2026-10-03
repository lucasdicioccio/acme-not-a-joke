{- | A series of helpers to work with keys.

Two kinds of keys are involved when getting a certificate:

* the account key, a 'JWK.JWK' which signs the requests sent to the ACME server
* the certificate key, an 'RSA.PrivateKey' which signs the CSR (see
  "Acme.NotAJoke.CertManagement") and that your TLS server needs to load

ACME servers refuse a CSR signed with the account key, hence you need one
key of each.
-}
module Acme.NotAJoke.KeyManagement (
    -- * JWK
    genJWKrsa4096,
    loadJWKFile,
    writeJWKFile,
    loadOrCreateJWKFile,

    -- * RSA keys
    genRSAKey,
    genRSAKey4096,
    jwkFromRSAKey,
    jwkToRSAKey,

    -- * PEM and DER formats for RSA keys
    encodeRSAKeyPEM,
    decodeRSAKeyPEM,
    encodeRSAKeyDER,
    decodeRSAKeyDER,
    loadRSAKeyPEM,
    writeRSAKeyPEM,
    loadOrCreateRSAKeyPEM,
) where

import Control.Lens (view)
import Data.Aeson (eitherDecode, encode)
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (isJust)
import System.Directory (doesFileExist)

import qualified Crypto.JOSE.JWA.JWK as JWA
import qualified Crypto.JOSE.JWK as JWK
import Crypto.JOSE.Types (Base64Integer (..))
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.Types (fromASN1, toASN1)
import qualified Data.PEM as PEM
import qualified Data.X509 as X509

-- | Generates and RSA-4096 bits key.
genJWKrsa4096 :: IO JWK.JWK
genJWKrsa4096 = JWK.genJWK (JWK.RSAGenParam (4096 `div` 8))

-- | Loads a JWK from a file.
loadJWKFile :: FilePath -> IO (Maybe JWK.JWK)
loadJWKFile = fmap (either (const Nothing) Just) . readJWKFile

-- | Writes a JWK to a file.
writeJWKFile :: JWK.JWK -> FilePath -> IO ()
writeJWKFile jwk path = LBS.writeFile path (encode jwk)

{- | Loads a JWK from a file, generating a RSA-4096 bits key and storing it at
this path if the file does not exist yet.

An existing file which is not a JWK is left untouched and reported as an
error.
-}
loadOrCreateJWKFile :: FilePath -> IO (Either String JWK.JWK)
loadOrCreateJWKFile path = do
    exists <- doesFileExist path
    if exists
        then readJWKFile path
        else do
            jwk <- genJWKrsa4096
            writeJWKFile jwk path
            pure (Right jwk)

readJWKFile :: FilePath -> IO (Either String JWK.JWK)
readJWKFile = fmap (eitherDecode . LBS.fromStrict) . ByteString.readFile

{- | Generates an RSA key of a given size in bits (with the usual 65537 public
exponent).
-}
genRSAKey :: Int -> IO RSA.PrivateKey
genRSAKey bits = snd <$> RSA.generate (bits `div` 8) 65537

-- | Generates and RSA-4096 bits key.
genRSAKey4096 :: IO RSA.PrivateKey
genRSAKey4096 = genRSAKey 4096

-- | Turns an RSA key into a JWK.
jwkFromRSAKey :: RSA.PrivateKey -> JWK.JWK
jwkFromRSAKey = JWK.fromRSA

{- | Extracts the RSA key of a JWK.

Fails for JWKs which are not RSA keys or which only hold a public key.
-}
jwkToRSAKey :: JWK.JWK -> Either String RSA.PrivateKey
jwkToRSAKey jwk =
    case view JWK.jwkMaterial jwk of
        JWA.RSAKeyMaterial params ->
            case view JWA.rsaPrivateKeyParameters params of
                Nothing -> Left "not a private key"
                -- JWKs may omit the primes, which the PEM and DER formats require
                Just (JWA.RSAPrivateKeyParameters _ Nothing) -> Left "RSA key without its prime factors"
                Just (JWA.RSAPrivateKeyParameters d (Just opt))
                    | isJust (JWA.rsaOth opt) -> Left "RSA key with more than two primes"
                    | otherwise ->
                        Right $
                            RSA.PrivateKey
                                (JWA.rsaPublicKey params)
                                (int d)
                                (int $ JWA.rsaP opt)
                                (int $ JWA.rsaQ opt)
                                (int $ JWA.rsaDp opt)
                                (int $ JWA.rsaDq opt)
                                (int $ JWA.rsaQi opt)
        _ -> Left "not an RSA key"
  where
    int :: Base64Integer -> Integer
    int (Base64Integer x) = x

{- | Encodes an RSA key as a PEM file content.

The output is the PKCS#1 format (@-----BEGIN RSA PRIVATE KEY-----@), which is
not encrypted.
-}
encodeRSAKeyPEM :: RSA.PrivateKey -> ByteString
encodeRSAKeyPEM key =
    PEM.pemWriteBS (PEM.PEM "RSA PRIVATE KEY" [] (encodeRSAKeyDER key))

{- | Decodes the first RSA key found in a PEM file content.

Supports unencrypted keys in PKCS#1 format (@-----BEGIN RSA PRIVATE KEY-----@,
what 'encodeRSAKeyPEM' and older versions of `openssl genrsa` write) and in
PKCS#8 format (@-----BEGIN PRIVATE KEY-----@, what newer versions of `openssl
genrsa` write).
-}
decodeRSAKeyPEM :: ByteString -> Either String RSA.PrivateKey
decodeRSAKeyPEM bytes = do
    pems <- PEM.pemParseBS bytes
    case filter isKey pems of
        [] -> Left "no private key in PEM content"
        (pem : _) -> decodeRSAKeyDER (PEM.pemContent pem)
  where
    isKey pem = PEM.pemName pem `elem` ["RSA PRIVATE KEY", "PRIVATE KEY"]

-- | Encodes an RSA key in DER (PKCS#1) format.
encodeRSAKeyDER :: RSA.PrivateKey -> ByteString
encodeRSAKeyDER key = encodeASN1' DER (toASN1 (X509.PrivKeyRSA key) [])

-- | Decodes an RSA key in DER format (either PKCS#1 or PKCS#8).
decodeRSAKeyDER :: ByteString -> Either String RSA.PrivateKey
decodeRSAKeyDER bytes = do
    asn1 <- first show (decodeASN1' DER bytes)
    (key, _) <- fromASN1 asn1
    case key of
        X509.PrivKeyRSA rsa -> Right rsa
        _ -> Left "not an RSA key"

-- | Loads an RSA key from a PEM file, see 'decodeRSAKeyPEM'.
loadRSAKeyPEM :: FilePath -> IO (Either String RSA.PrivateKey)
loadRSAKeyPEM = fmap decodeRSAKeyPEM . ByteString.readFile

{- | Writes an RSA key to a PEM file, see 'encodeRSAKeyPEM'.

The key is not encrypted and the file gets the default permissions of your
process: mind where you store it.
-}
writeRSAKeyPEM :: RSA.PrivateKey -> FilePath -> IO ()
writeRSAKeyPEM key path = ByteString.writeFile path (encodeRSAKeyPEM key)

{- | Loads an RSA key from a PEM file, generating a RSA-4096 bits key and
storing it at this path if the file does not exist yet.

An existing file which is not an RSA key is left untouched and reported as an
error.
-}
loadOrCreateRSAKeyPEM :: FilePath -> IO (Either String RSA.PrivateKey)
loadOrCreateRSAKeyPEM path = do
    exists <- doesFileExist path
    if exists
        then loadRSAKeyPEM path
        else do
            key <- genRSAKey4096
            writeRSAKeyPEM key path
            pure (Right key)
