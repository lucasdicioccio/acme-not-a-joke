{-# LANGUAGE TupleSections #-}

module Main (main) where

import Control.Concurrent (forkIO, killThread)
import Control.Exception (SomeException, bracket, try)
import Control.Monad (unless)
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Data.ASN1.Types (ASN1CharacterString, ASN1StringEncoding (UTF8), asn1CharacterString, getObjectID)
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.X509 as X509
import Network.HTTP.Types (status200)
import qualified Network.Socket as Socket
import qualified Network.TLS as TLS
import Network.Wai (responseLBS)
import Network.Wai.Handler.Warp (Port, Settings, defaultSettings, openFreePort, setOnException)
import Network.Wai.Handler.WarpTLS (runTLSSocket)
import System.Exit (exitFailure)
import Time.Types (Date (..), DateTime (..), Month (..), TimeOfDay (..))

import Acme.NotAJoke.CertManagement (encodeCertificateChain)
import Acme.NotAJoke.KeyManagement (encodeRSAKeyPEM, genRSAKey)
import Acme.NotAJoke.Wai.WarpTLS

main :: IO ()
main = do
    credA <- selfSigned "a.test"
    credB <- selfSigned "b.test"
    storeLooksUpCredentials credA credB
    credentialIsReadFromPEM
    serverPresentsLiveCredentials credA credB
    putStrLn "ok"

storeLooksUpCredentials :: TLS.Credential -> TLS.Credential -> IO ()
storeLooksUpCredentials credA credB = do
    store <- newCertificateStore
    let served name = fmap fst <$> lookupCredential store name

    empty <- served (Just "a.test")
    check "empty store has no credential" (empty == Nothing)

    setCredential store credA
    noName <- served Nothing
    check "default credential is presented without server name" (noName == Just (fst credA))
    unknown <- served (Just "unknown.test")
    check "default credential is presented for an unknown name" (unknown == Just (fst credA))

    setCredentialFor store "B.test" credB
    named <- served (Just "b.TEST")
    check "named credential is presented regardless of case" (named == Just (fst credB))
    other <- served (Just "a.test")
    check "default credential still is presented for other names" (other == Just (fst credA))

    hooked <- sniCredentials store (Just "b.test")
    check "the hook returns the credential of the name" (chains hooked == [fst credB])

    deleteCredentialFor store "b.test"
    deleted <- served (Just "b.test")
    check "deleted name falls back to the default credential" (deleted == Just (fst credA))

    clearCredentials store
    cleared <- sniCredentials store Nothing
    check "cleared store has no credential" (null (chains cleared))
  where
    chains (TLS.Credentials creds) = map fst creds

credentialIsReadFromPEM :: IO ()
credentialIsReadFromPEM = do
    key <- genRSAKey 2048
    chain <- selfSignedChain key "pem.test"
    let X509.CertificateChain certs = chain
    let loaded = credentialFromPEM (encodeCertificateChain certs) (encodeRSAKeyPEM key)
    check "credential is read from the PEM formats of the library" (fmap fst loaded == Right chain)
    check "credential without a key is refused" (isLeft (credentialFromPEM (encodeCertificateChain certs) ""))
  where
    isLeft = either (const True) (const False)

{- | Runs a warp-tls server on the store, and checks which certificate TLS
clients get while the store changes.
-}
serverPresentsLiveCredentials :: TLS.Credential -> TLS.Credential -> IO ()
serverPresentsLiveCredentials credA credB = do
    store <- newCertificateStore
    (port, sock) <- openFreePort
    let app _ respond = respond $ responseLBS status200 [] "hello"
    bracket (forkIO $ runTLSSocket (liveTlsSettings store) quiet sock app) killThread $ \_ -> do
        before <- presented port "a.test"
        check "handshake fails while the store is empty" (before == Nothing)

        setCredential store credA
        first <- presented port "a.test"
        check "running server presents the credential added to the store" (first == Just (fst credA))

        setCredential store credB
        renewed <- presented port "a.test"
        check "running server presents the credential replacing it" (renewed == Just (fst credB))

        setCredentialFor store "a.test" credA
        named <- presented port "a.test"
        check "running server presents the credential of the server name" (named == Just (fst credA))
        other <- presented port "b.test"
        check "running server presents the default credential for other names" (other == Just (fst credB))

-- | Failed handshakes are expected: they are not logged.
quiet :: Settings
quiet = setOnException (\_ _ -> pure ()) defaultSettings

{- | The certificate chain a server on localhost presents to a client asking
for a server name, if the handshake succeeds.
-}
presented :: Port -> TLS.HostName -> IO (Maybe X509.CertificateChain)
presented port name = do
    seen <- newIORef Nothing
    let hooks =
            TLS.defaultClientHooks
                { TLS.onServerCertificate = \_ _ _ chain -> do
                    writeIORef seen (Just chain)
                    -- test certificates are self-signed
                    pure []
                }
    let params =
            (TLS.defaultParamsClient name "")
                { TLS.clientHooks = hooks
                , TLS.clientSupported = TLS.defaultSupported
                }
    res <- try (bracket (connect port) Socket.close (handshake params))
    case res :: Either SomeException () of
        Left _ -> pure Nothing
        Right () -> readIORef seen
  where
    handshake params sock = do
        ctx <- TLS.contextNew sock params
        TLS.handshake ctx
        TLS.bye ctx

connect :: Port -> IO Socket.Socket
connect port = do
    sock <- Socket.socket Socket.AF_INET Socket.Stream Socket.defaultProtocol
    Socket.connect sock (Socket.SockAddrInet (fromIntegral port) (Socket.tupleToHostAddress (127, 0, 0, 1)))
    pure sock

selfSigned :: String -> IO TLS.Credential
selfSigned name = do
    key <- genRSAKey 2048
    chain <- selfSignedChain key name
    pure (chain, X509.PrivKeyRSA key)

selfSignedChain :: RSA.PrivateKey -> String -> IO X509.CertificateChain
selfSignedChain key name = do
    signed <- X509.objectToSignedExactF sign certificate
    pure $ X509.CertificateChain [signed]
  where
    alg :: X509.SignatureALG
    alg = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_RSA

    sign bytes = do
        signature <- PKCS15.signSafer (Just SHA256) key bytes
        either (fail . show) (pure . (,alg)) signature

    commonName :: ASN1CharacterString
    commonName = asn1CharacterString UTF8 name

    dn :: X509.DistinguishedName
    dn = X509.DistinguishedName [(getObjectID X509.DnCommonName, commonName)]

    midnight :: TimeOfDay
    midnight = TimeOfDay 0 0 0 0

    certificate :: X509.Certificate
    certificate =
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
