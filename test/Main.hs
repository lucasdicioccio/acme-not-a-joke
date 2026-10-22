{-# LANGUAGE DataKinds #-}

-- | Round-trips of the PKI-formats helpers, and pure helpers of the dance.
module Main (main) where

import Control.Monad (unless)
import Data.Aeson (decode)
import qualified Data.ByteString.Lazy as LByteString
import qualified Data.ByteString as ByteString
import Data.List.NonEmpty (NonEmpty (..))
import System.Directory (getTemporaryDirectory, removeFile)
import System.Exit (exitFailure)
import System.FilePath ((</>))

import Acme.NotAJoke.Api.Authorization
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Challenge (Challenge (..), Token (..), isDNS01, isHTTP01)
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
  where
    isLeft :: Either a b -> Bool
    isLeft = either (const True) (const False)

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
