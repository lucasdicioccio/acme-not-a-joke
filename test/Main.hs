{-# LANGUAGE DataKinds #-}

-- | Round-trips of the PKI-formats helpers, and pure helpers of the dance.
module Main (main) where

import Control.Lens (preview, view)
import Control.Monad (forM_, unless)
import Data.Aeson (Value (..), decode, decodeStrict, encode, object, (.=))
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as LByteString
import qualified Data.ByteString as ByteString
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Encoding
import System.Directory (getTemporaryDirectory, removeFile)
import System.Exit (exitFailure)
import System.FilePath ((</>))

import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.JWS as JWS
import qualified Data.X509 as X509

import Acme.NotAJoke.Api.Authorization
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Challenge (Challenge (..), Token (..), isDNS01, isHTTP01)
import Acme.NotAJoke.Api.Endpoint (Endpoint (..))
import Acme.NotAJoke.Api.JWS (AcmeHeader, KID (..), acmeJWSAlg, jwkSign, kidSign, setAcmeJWSAlg)
import Acme.NotAJoke.Api.Nonce (Nonce (..))
import Acme.NotAJoke.Api.Revocation
import Acme.NotAJoke.CertManagement
import Acme.NotAJoke.Client (dns01RecordName, isWildcardDomain, pickChallenges, wildcardBase)
import Acme.NotAJoke.KeyManagement

main :: IO ()
main = do
    tmp <- getTemporaryDirectory
    let keyPath = tmp </> "acme-not-a-joke-test.key.pem"
    let csrPath = tmp </> "acme-not-a-joke-test.csr"

    key <- genRSAKey 2048

    -- keys
    check "RSA key, DER round-trip" $
        decodeRSAKeyDER (encodeRSAKeyDER key) == Right key
    check "RSA key, PEM round-trip" $
        decodeRSAKeyPEM (encodeRSAKeyPEM key) == Right key
    check "RSA key, JWK round-trip" $
        jwkToRSAKey (jwkFromRSAKey key) == Right key
    check "RSA key, not a key" $
        isLeft (decodeRSAKeyPEM "garbage")
    writeRSAKeyPEM key keyPath
    loaded <- loadRSAKeyPEM keyPath
    check "RSA key, file round-trip" $
        loaded == Right key
    reloaded <- loadOrCreateRSAKeyPEM keyPath
    check "RSA key, existing file is kept" $
        reloaded == Right key
    removeFile keyPath

    -- CSRs
    Right csr <- createCSR key ("example.dicioccio.fr" :| ["*.example.dicioccio.fr"])
    check "CSR, PEM round-trip" $
        (encodeCSRPEM csr >>= decodeCSRPEM >>= csrToDER) == csrToDER csr
    Right () <- writeCSRPEM csr csrPath
    fromPEM <- loadCSR csrPath
    check "CSR, PEM file round-trip" $
        (fromPEM >>= csrToDER) == csrToDER csr
    Right () <- writeCSRDER csr csrPath
    fromDER <- loadCSR csrPath
    check "CSR, DER file round-trip" $
        (fromDER >>= csrToDER) == csrToDER csr
    legacy <- loadDER csrPath
    check "CSR, same as loadDER" $
        csrToDER (CSR legacy) == csrToDER csr
    removeFile csrPath
    invalid <- createCSR key ("exämple.dicioccio.fr" :| [])
    check "CSR, non-ASCII names are rejected" $
        isLeft (invalid >>= csrToDER)

    -- certificates
    check "certificates, PEM round-trip" $
        fmap encodeCertificateChain (decodeCertificateChain (certificate <> certificate))
            == Right (certificate <> certificate)
    check "certificates, not a certificate" $
        isLeft (decodeCertificateChain "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    -- wildcard orders
    check "wildcard, base domain" $
        wildcardBase "*.example.com" == "example.com" && wildcardBase "example.com" == "example.com"
    check "wildcard, detected" $
        isWildcardDomain "*.example.com" && not (isWildcardDomain "example.com")
    check "dns-01, record name of a domain" $
        dns01RecordName (AuthorizationIdentifier DNSAuthorization "example.com") == "_acme-challenge.example.com"
    check "dns-01, record name of a wildcard is the one of its base domain" $
        dns01RecordName (AuthorizationIdentifier DNSAuthorization "*.example.com") == "_acme-challenge.example.com"
    Just wildcardAuthz <- pure $ decodeAuthorization (authorizationJSON "pending" True)
    Just apexAuthz <- pure $ decodeAuthorization (authorizationJSON "pending" False)
    Just reusedAuthz <- pure $ decodeAuthorization (authorizationJSON "valid" False)
    Just expiredAuthz <- pure $ decodeAuthorization (authorizationJSON "expired" False)
    check "authorization, wildcard flag is read" $
        wildcard wildcardAuthz == Just True && wildcard apexAuthz == Nothing
    check "dns-01, wildcard and apex both get a challenge" $
        fmap (map (\(tag, _, _) -> tag)) (pickChallenges isDNS01 [(1 :: Int, wildcardAuthz), (2, apexAuthz)]) == Right [1, 2]
    check "dns-01, challenges of wildcard and apex have their own tokens" $
        fmap (map (\(_, _, c) -> challengeToken c)) (pickChallenges isDNS01 [(1 :: Int, wildcardAuthz), (2, apexAuthz)])
            == Right [Token "dns-token-wildcard", Token "dns-token-apex"]
    check "dns-01, valid authorizations are skipped" $
        fmap (map (\(tag, _, _) -> tag)) (pickChallenges isDNS01 [(1 :: Int, wildcardAuthz), (2, reusedAuthz)]) == Right [1]
    check "http-01, a wildcard cannot be validated" $
        either fst (const 0) (pickChallenges isHTTP01 [(1 :: Int, apexAuthz), (2, wildcardAuthz)]) == 2
    check "an expired authorization fails the order" $
        isLeft (pickChallenges isDNS01 [(1 :: Int, expiredAuthz)])

    -- revocations
    Right [cert] <- pure $ decodeCertificateChain certificate
    -- (a Base64DER holds base64url content, which csrToDER decodes)
    Right der <- pure $ csrToDER (CSR (revokedCertificate (revocation Nothing cert)))
    check "revocation, certificate is sent in base64url DER" $
        fmap (encodeCertificateChain . pure) (X509.decodeSignedCertificate der) == Right certificate
    check "revocation, payload without reason" $
        decode (serializeRevocation (revocation Nothing cert))
            == Just (object ["certificate" .= revokedCertificate (revocation Nothing cert)])
    check "revocation, payload with reason" $
        decode (serializeRevocation (revocation (Just KeyCompromise) cert))
            == Just (object ["certificate" .= revokedCertificate (revocation Nothing cert), "reason" .= (1 :: Int)])
    check "revocation, reason codes skip 7" $
        map revocationReasonCode [minBound .. maxBound] == [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]
    let ep = Endpoint "https://acme.test/revoke-cert" :: Endpoint "revokeCert"
    let payload = serializeRevocation (revocation Nothing cert)
    byCertKey <- jwkSign (jwkFromRSAKey key) ep (Nonce "nonce") payload
    check "revocation, signed with the certificate key carries a jwk" $
        protectedHeaderHas "jwk" (encode <$> byCertKey) && not (protectedHeaderHas "kid" (encode <$> byCertKey))
    byAccount <- kidSign (jwkFromRSAKey key) ep (KID "https://acme.test/acct/1") (Nonce "nonce") payload
    check "revocation, signed with the account carries a kid" $
        protectedHeaderHas "kid" (encode <$> byAccount) && not (protectedHeaderHas "jwk" (encode <$> byAccount))

    -- JWS algorithms
    let rsa = jwkFromRSAKey key
    ecP256 <- genJWKecP256
    ecP384 <- genJWKecP384
    ed25519 <- genJWKed25519
    oct <- JWK.genJWK (JWK.OctGenParam 32)
    check "JWS alg, from the key" $
        (map acmeJWSAlg [rsa, ecP256, ecP384, ed25519] :: [Either JWS.Error JWS.Alg])
            == map Right [JWS.RS256, JWS.ES256, JWS.ES384, JWS.EdDSA]
    check "JWS alg, symmetric keys are refused" $
        isLeft (acmeJWSAlg oct :: Either JWS.Error JWS.Alg)
    check "JWS alg, pinned by the key" $
        acmeJWSAlg (setAcmeJWSAlg JWS.PS256 rsa) == (Right JWS.PS256 :: Either JWS.Error JWS.Alg)
    check "JWS alg, MAC algorithms cannot be pinned" $
        isLeft (acmeJWSAlg (setAcmeJWSAlg JWS.HS256 oct) :: Either JWS.Error JWS.Alg)
    let kid = KID "https://acme.test/acct/1"
    forM_ [("RS256", rsa), ("ES256", ecP256), ("ES384", ecP384), ("EdDSA", ed25519), ("PS256", setAcmeJWSAlg JWS.PS256 rsa)] $ \(alg, jwk) -> do
        byJwk <- jwkSign jwk ep (Nonce "nonce") payload
        check ("JWS alg, jwk signature with " <> alg) =<< verifiesWith jwk byJwk
        check ("JWS alg, jwk header announces " <> alg) $
            protectedHeaderParam "alg" (encode <$> byJwk) == Just (String (Text.pack alg))
        byKid <- kidSign jwk ep kid (Nonce "nonce") payload
        check ("JWS alg, kid signature with " <> alg) =<< verifiesWith jwk byKid
        check ("JWS alg, kid header announces " <> alg) $
            protectedHeaderParam "alg" (encode <$> byKid) == Just (String (Text.pack alg))
    mismatched <- kidSign (setAcmeJWSAlg JWS.ES256 rsa) ep kid (Nonce "nonce") payload
    check "JWS alg, an algorithm which does not fit the key fails" $
        isLeft mismatched
    byOct <- kidSign oct ep kid (Nonce "nonce") payload
    check "JWS alg, signing with a symmetric key fails" $
        isLeft byOct
  where
    isLeft :: Either a b -> Bool
    isLeft = either (const True) (const False)

{- | Whether the protected header of a (JSON-serialized, flattened) JWS has a
given parameter.
-}
protectedHeaderHas :: KeyMap.Key -> Either e LByteString.ByteString -> Bool
protectedHeaderHas param = maybe False (const True) . protectedHeaderParam param

{- | A parameter of the protected header of a (JSON-serialized, flattened)
JWS.
-}
protectedHeaderParam :: KeyMap.Key -> Either e LByteString.ByteString -> Maybe Value
protectedHeaderParam param (Right jws) =
    case decode jws of
        Just (Object o) | Just (String protected) <- KeyMap.lookup "protected" o ->
            case decodeStrict =<< preview JWK.base64url (Encoding.encodeUtf8 protected) of
                Just (Object hdr) -> KeyMap.lookup param hdr
                _ -> Nothing
        _ -> Nothing
protectedHeaderParam _ (Left _) = Nothing

-- | Whether a JWS was signed (successfully) by the public part of a key.
verifiesWith :: JWK.JWK -> Either JWS.Error (JWS.FlattenedJWS AcmeHeader) -> IO Bool
verifiesWith jwk (Right jws) =
    case view JWK.asPublicKey jwk of
        Nothing -> pure False
        Just pub -> do
            res <- JWS.runJOSE (JWS.verifyJWS' pub jws) :: IO (Either JWS.Error LByteString.ByteString)
            pure $ either (const False) (const True) res
verifiesWith _ (Left _) = pure False

decodeAuthorization :: LByteString.ByteString -> Maybe (Authorization "authorization-inspected")
decodeAuthorization = decode

challengeToken :: Challenge "challenge-unspecified" -> Token
challengeToken = token

{- | An authorization for example.com, in the shape Let's Encrypt gives:
wildcard authorizations only offer a DNS-01 challenge.
-}
authorizationJSON :: LByteString.ByteString -> Bool -> LByteString.ByteString
authorizationJSON st isWildcard =
    mconcat
        [ "{\"status\":\"" <> st <> "\""
        , ",\"identifier\":{\"type\":\"dns\",\"value\":\"example.com\"}"
        , ",\"expires\":\"2026-10-29T20:00:00Z\""
        , ",\"challenges\":["
        , if isWildcard
            then challengeJSON "dns-01" "dns-token-wildcard"
            else challengeJSON "http-01" "http-token-apex" <> "," <> challengeJSON "dns-01" "dns-token-apex"
        , "]"
        , if isWildcard then ",\"wildcard\":true" else ""
        , "}"
        ]
  where
    challengeJSON ty tok =
        "{\"type\":\"" <> ty <> "\",\"url\":\"https://acme.test/chall/" <> tok <> "\",\"status\":\"pending\",\"token\":\"" <> tok <> "\"}"

check :: String -> Bool -> IO ()
check name ok = do
    putStrLn $ (if ok then "ok   " else "FAIL ") <> name
    unless ok exitFailure

-- | A self-signed certificate from `openssl req -x509`.
certificate :: ByteString.ByteString
certificate =
    "\
    \-----BEGIN CERTIFICATE-----\n\
    \MIIDHzCCAgegAwIBAgIUe6GwrrJYtHXoUUvOfo+0k65J9b8wDQYJKoZIhvcNAQEL\n\
    \BQAwHzEdMBsGA1UEAwwUZXhhbXBsZS5kaWNpb2NjaW8uZnIwHhcNMjYxMDAzMjAw\n\
    \NTU4WhcNMzYwOTMwMjAwNTU4WjAfMR0wGwYDVQQDDBRleGFtcGxlLmRpY2lvY2Np\n\
    \by5mcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI5pzazL8wVF1rLi\n\
    \yC+gf24C0p5bnC/7Qcis7778BEbhf/inyvSh4MIb478OB4HCMgxwACZPx5v4+G+i\n\
    \eJRC2+rfF6j8aP6Q6uLNviS6n3gzlY0HvUdd7RblwSvDJBsgXhaW244EM1V+eaDk\n\
    \pS89WlRgvS0loIIxS2c4qZO5JtLCVaeXuCXjRZRd7fzvPiGjRePr3+yNvm/ni0VN\n\
    \hYpg/6BIJ/fvWznnex8GNVL1/PH0EWW3p+GUn+64kHDlO0GhCnssP0DzU4DVKWVq\n\
    \FTjVjVq74gA7F3VcXxQRzNDnySJmnI7PlafF8E55Wi7kdHhbXD5WAFj8PdxqAfil\n\
    \GzMBJnkCAwEAAaNTMFEwHQYDVR0OBBYEFAtAWeP1+UJzfxKHf7gynaAtDYz3MB8G\n\
    \A1UdIwQYMBaAFAtAWeP1+UJzfxKHf7gynaAtDYz3MA8GA1UdEwEB/wQFMAMBAf8w\n\
    \DQYJKoZIhvcNAQELBQADggEBABqTTUXnNc//sjXn+PCjhUPZ5RBJ/W624pH7MwIT\n\
    \9xncI0zkkp5OMyLzwCIVwlkA//y/5Sv7zSRXAGwrUajKR8hmBGE1q8yE0fwv6Drj\n\
    \6LxXScSjpTbXtLdvuRU/CcV+xToc3ApfyyB37XOtugUxPizHHxeFQxF2aBSLToXZ\n\
    \15MQ9w+JIgLJP/cFrSKYHGgqrTdQOZ/ouSpGBpwu7jWioN5HaL4WLWyX0GTzX4SV\n\
    \foVtfxa84UV77PyoQ8m0VH2zilqvgRld2NKUIGABrSJeHiVvZ7++fLrDY5llzT2K\n\
    \4PixgIzdV81Bt88QEvMdDZcf3SSbRS018YfqTqNbs7ntG8k=\n\
    \-----END CERTIFICATE-----\n\
    \"
