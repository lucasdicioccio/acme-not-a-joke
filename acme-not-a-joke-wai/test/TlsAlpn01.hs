{-# LANGUAGE TupleSections #-}

module Main (main) where

import Control.Concurrent (forkIO, killThread)
import Control.Exception (SomeException, bracket, try)
import Control.Monad (unless)
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1 (..), ASN1StringEncoding (UTF8), asn1CharacterString, getObjectID)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.X509 as X509
import Data.X509.Validation (SignatureVerification (..), verifySignedSignature)
import Network.HTTP.Types (status200)
import qualified Network.Socket as Socket
import qualified Network.TLS as TLS
import Network.Wai (responseLBS)
import Network.Wai.Handler.Warp (Port, Settings, defaultSettings, openFreePort, setOnException)
import Network.Wai.Handler.WarpTLS (runTLSSocket)
import System.Exit (exitFailure)
import Time.Types (Date (..), DateTime (..), Month (..), TimeOfDay (..))

import Acme.NotAJoke.Api.Validation (KeyAuthorization (..))
import Acme.NotAJoke.CertManagement (acmeIdentifierDigest, acmeIdentifierOID, acmeTLSALPNProtocol)
import Acme.NotAJoke.KeyManagement (genRSAKey)
import Acme.NotAJoke.Wai.TlsAlpn01
import Acme.NotAJoke.Wai.WarpTLS (liveTlsSettings, newCertificateStore, setCredential)

keyAuth :: KeyAuthorization
keyAuth = KeyAuthorization "token.thumbprint"

main :: IO ()
main = do
    key <- genRSAKey 2048
    Right challenge <- challengeCredential key "a.test" keyAuth
    challengeCertificateHasTheExtension key challenge
    storeLooksUpChallenges challenge
    serverAnswersChallenges challenge
    putStrLn "ok"

challengeCertificateHasTheExtension :: RSA.PrivateKey -> TLS.Credential -> IO ()
challengeCertificateHasTheExtension key (X509.CertificateChain chain, _) = do
    check "the challenge certificate is alone in its chain" (length chain == 1)
    leaf <- case chain of
        (leaf : _) -> pure leaf
        [] -> fail "empty chain"
    let cert = X509.getCertificate leaf
        X509.Extensions exts = X509.certExtensions cert
        acme = [e | e <- concat exts, X509.extRawOID e == acmeIdentifierOID]
    check "the certificate has one acmeIdentifier extension" (length acme == 1)
    check "the acmeIdentifier extension is critical" (all X509.extRawCritical acme)
    check "the digest is the SHA-256 of the key authorization" (acmeIdentifierDigest keyAuth == expectedDigest)
    check
        "the acmeIdentifier extension holds the digest as an octet string"
        (map (decodeASN1' DER . X509.extRawContent) acme == [Right [OctetString expectedDigest]])
    check
        "the certificate is for the name only"
        (X509.extensionGet (X509.certExtensions cert) == Just (X509.ExtSubjectAltName [X509.AltNameDNS "a.test"]))
    check "the certificate is for the key" (X509.certPubKey cert == X509.PubKeyRSA (RSA.private_pub key))
    check
        "the certificate is self-signed"
        (verifySignedSignature leaf (X509.certPubKey cert) == SignaturePass)
  where
    -- sha256sum of "token.thumbprint"
    expectedDigest :: ByteString
    expectedDigest =
        ByteString.pack
            [ 0xeb, 0x5a, 0xc1, 0x67, 0xfe, 0x24, 0x9c, 0x76, 0xe5, 0x3b, 0x43, 0x0d, 0xa3, 0x11, 0x6c, 0x5d
            , 0x9f, 0xde, 0x4c, 0x55, 0x07, 0xba, 0x6d, 0x01, 0xe8, 0x85, 0x51, 0x6e, 0x1b, 0xd4, 0x9f, 0x92
            ]

storeLooksUpChallenges :: TLS.Credential -> IO ()
storeLooksUpChallenges challenge = do
    store <- newTlsAlpn01Store
    insertTlsAlpn01 store "A.test" challenge
    found <- fmap fst <$> lookupTlsAlpn01 store "a.TEST"
    check "challenges are looked up regardless of case" (found == Just (fst challenge))
    names <- listTlsAlpn01 store
    check "challenges are listed" (names == ["a.test"])
    deleteTlsAlpn01 store "a.test"
    deleted <- lookupTlsAlpn01 store "a.test"
    check "deleted challenges are gone" (null (fmap fst deleted))

{- | Runs a warp-tls server with a regular certificate and the challenges of a
store, and checks what TLS clients get.
-}
serverAnswersChallenges :: TLS.Credential -> IO ()
serverAnswersChallenges challenge = do
    regular <- selfSigned "a.test"
    certificates <- newCertificateStore
    setCredential certificates regular
    challenges <- newTlsAlpn01Store
    (port, sock) <- openFreePort
    let app _ respond = respond $ responseLBS status200 [] "hello"
    let settings = withTlsAlpn01 challenges (liveTlsSettings certificates)
    bracket (forkIO $ runTLSSocket settings quiet sock app) killThread $ \_ -> do
        plain <- handshake port "a.test" Nothing TLS.TLS13
        check "a client without ALPN gets the regular certificate" (plain == Just (fst regular, Nothing))
        h2 <- handshake port "a.test" (Just ["h2", "http/1.1"]) TLS.TLS13
        check "a client asking for h2 still gets it" (h2 == Just (fst regular, Just "h2"))
        http1 <- handshake port "a.test" (Just ["http/1.1"]) TLS.TLS13
        check "a client asking for http/1.1 still gets it" (http1 == Just (fst regular, Just "http/1.1"))

        none <- handshake port "a.test" (Just [acmeTLSALPNProtocol]) TLS.TLS13
        check "acme-tls/1 handshakes fail without a challenge" (none == Nothing)

        insertTlsAlpn01 challenges "a.test" challenge
        answered <- handshake port "a.test" (Just [acmeTLSALPNProtocol]) TLS.TLS13
        check "acme-tls/1 handshakes get the challenge certificate" (answered == Just (fst challenge, Just acmeTLSALPNProtocol))
        other <- handshake port "b.test" (Just [acmeTLSALPNProtocol]) TLS.TLS13
        check "acme-tls/1 handshakes for another name fail" (other == Nothing)
        regularStill <- handshake port "a.test" (Just ["h2", "http/1.1"]) TLS.TLS13
        check "other handshakes still get the regular certificate" (regularStill == Just (fst regular, Just "h2"))
        tls12 <- handshake port "a.test" (Just [acmeTLSALPNProtocol]) TLS.TLS12
        check "acme-tls/1 handshakes over TLS 1.2 do not get the challenge certificate" (fmap fst tls12 /= Just (fst challenge))
        afterTls12 <- handshake port "a.test" (Just ["http/1.1"]) TLS.TLS12
        check "TLS 1.2 handshakes get the regular certificate" (afterTls12 == Just (fst regular, Just "http/1.1"))

        deleteTlsAlpn01 challenges "a.test"
        removed <- handshake port "a.test" (Just [acmeTLSALPNProtocol]) TLS.TLS13
        check "acme-tls/1 handshakes fail once the challenge is removed" (removed == Nothing)

-- | Failed handshakes are expected: they are not logged.
quiet :: Settings
quiet = setOnException (\_ _ -> pure ()) defaultSettings

{- | The certificate chain a server on localhost presents to a client asking
for a server name and some protocols, and the protocol chosen by the server,
if the handshake succeeds.
-}
handshake :: Port -> TLS.HostName -> Maybe [ByteString] -> TLS.Version -> IO (Maybe (X509.CertificateChain, Maybe ByteString))
handshake port name protocols version = do
    seen <- newIORef Nothing
    let hooks =
            TLS.defaultClientHooks
                { TLS.onServerCertificate = \_ _ _ chain -> do
                    writeIORef seen (Just chain)
                    -- test certificates are self-signed
                    pure []
                , TLS.onSuggestALPN = pure protocols
                }
    let params =
            (TLS.defaultParamsClient name "")
                { TLS.clientHooks = hooks
                , TLS.clientSupported = TLS.defaultSupported{TLS.supportedVersions = [version]}
                }
    res <- try (bracket (connect port) Socket.close (run params))
    case res :: Either SomeException (Maybe ByteString) of
        Left _ -> pure Nothing
        Right protocol -> fmap (,protocol) <$> readIORef seen
  where
    run params sock = do
        ctx <- TLS.contextNew sock params
        TLS.handshake ctx
        protocol <- TLS.getNegotiatedProtocol ctx
        TLS.bye ctx
        pure protocol

connect :: Port -> IO Socket.Socket
connect port = do
    sock <- Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
    Socket.connect sock (Socket.SockAddrInet (fromIntegral port) (Socket.tupleToHostAddress (127, 0, 0, 1)))
    pure sock

selfSigned :: String -> IO TLS.Credential
selfSigned name = do
    key <- genRSAKey 2048
    signed <- X509.objectToSignedExactF (sign key) (certificate key)
    pure (X509.CertificateChain [signed], X509.PrivKeyRSA key)
  where
    alg :: X509.SignatureALG
    alg = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA

    sign key bytes = do
        signature <- PKCS15.signSafer (Just SHA256) key bytes
        either (fail . show) (pure . (,alg)) signature

    dn :: X509.DistinguishedName
    dn = X509.DistinguishedName [(getObjectID X509.DnCommonName, asn1CharacterString UTF8 name)]

    midnight :: TimeOfDay
    midnight = TimeOfDay 0 0 0 0

    certificate key =
        X509.Certificate
            { X509.certVersion = 2
            , X509.certSerial = 1
            , X509.certSignatureAlg = alg
            , X509.certIssuerDN = dn
            , X509.certValidity = (DateTime (Date 2020 January 1) midnight, DateTime (Date 2120 January 1) midnight)
            , X509.certSubjectDN = dn
            , X509.certPubKey = X509.PubKeyRSA (RSA.private_pub key)
            , X509.certExtensions = X509.Extensions Nothing
            }

check :: String -> Bool -> IO ()
check name ok = do
    putStrLn $ (if ok then "pass: " else "FAIL: ") <> name
    unless ok exitFailure
