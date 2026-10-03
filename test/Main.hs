-- | Round-trips of the PKI-formats helpers.
module Main (main) where

import Control.Monad (unless)
import qualified Data.ByteString as ByteString
import Data.List.NonEmpty (NonEmpty (..))
import System.Directory (getTemporaryDirectory, removeFile)
import System.Exit (exitFailure)
import System.FilePath ((</>))

import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.CertManagement
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
  where
    isLeft :: Either a b -> Bool
    isLeft = either (const True) (const False)

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
