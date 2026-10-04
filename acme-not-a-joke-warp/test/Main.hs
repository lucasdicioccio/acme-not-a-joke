{-# LANGUAGE TupleSections #-}

module Main (main) where

import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Exception (SomeException, bracket, throwIO, try)
import Control.Monad (unless)
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Data.ASN1.Types (ASN1CharacterString, ASN1StringEncoding (UTF8), asn1CharacterString, getObjectID)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import Data.Either (isLeft)
import Data.IORef (IORef, atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Text as Text
import Data.Time.Calendar (fromGregorian, toGregorian)
import Data.Time.Clock (UTCTime (..), addUTCTime)
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Data.X509 as X509
import Network.HTTP.Types (Status, hHost, hLocation, status200, status308, status400)
import qualified Network.Socket as Socket
import qualified Network.Socket.ByteString as SocketBS
import qualified Network.TLS as TLS
import Network.Wai (Application, Request, defaultRequest, rawPathInfo, rawQueryString, requestHeaderHost, requestHeaders, responseHeaders, responseLBS, responseStatus)
import Network.Wai.Handler.Warp (Port, defaultSettings, openFreePort, setOnException, setPort)
import System.Directory (createDirectoryIfMissing, doesFileExist, getTemporaryDirectory, removePathForcibly)
import System.Exit (exitFailure)
import System.FilePath ((</>))
import System.Timeout (timeout)
import Time.Types (Date (..), DateTime (..), TimeOfDay (..))

import Acme.NotAJoke.Api.Challenge (Token (..))
import Acme.NotAJoke.Api.Validation (KeyAuthorization (..))
import Acme.NotAJoke.CertManagement (decodeCertificateChain, encodeCertificateChain)
import Acme.NotAJoke.KeyManagement (genRSAKey, writeRSAKeyPEM)
import Acme.NotAJoke.Wai.Http01 (deleteChallenge, insertChallenge)
import Acme.NotAJoke.Wai.WarpTLS (lookupCredential)
import Acme.NotAJoke.Warp

main :: IO ()
main = do
    renewalTimes
    domainsAreChecked
    withStateDirectory certificateIsObtainedStoredAndRenewed
    withStateDirectory failuresAreRetried
    withStateDirectory unusableFilesAreReplaced
    withStateDirectory eachDomainHasItsCertificate
    redirectsToHttps
    withStateDirectory serversGetTheirCertificate
    putStrLn "ok"

-- | Midnight, some days after the start of the test clock.
day :: Integer -> UTCTime
day n = UTCTime (fromGregorian 2030 1 1) 0 `plusDays` n

plusDays :: UTCTime -> Integer -> UTCTime
plusDays t n = addUTCTime (fromInteger n * 86400) t

renewalTimes :: IO ()
renewalTimes = do
    let validity = Validity (day 0) (day 90)
    check "renews after two thirds of the validity" (renewAfterTwoThirds validity == day 60)
    check "renews a fixed duration before the end" (renewBefore (10 * 86400) validity == day 80)
    check "first retry is after two minutes" (exponentialRetry 1 == 120)
    check "retry delays double" (map exponentialRetry [2, 3, 4] == [240, 480, 960])
    check "retry delays are capped" (exponentialRetry 1000 == 6 * 3600)

domainsAreChecked :: IO ()
domainsAreChecked = do
    check "a path is not a domain" . isLeft =<< create ("../etc" :| [])
    check "a wildcard is not a domain" . isLeft =<< create ("*.a.test" :| [])
    check "an empty name is not a domain" . isLeft =<< create ("a.test" :| [""])
    check "host names are domains" . not . isLeft =<< create ("a.test" :| ["B.Test", "xn--bcher-kva.test"])
  where
    create names = do
        certificates <- newCertificateStore
        fmap (const ()) <$> newCertificateManager (defaultManagerSettings names "unused") (\_ _ -> pure (Left "unused")) certificates

-- | A clock, an issuer and the events of a manager under test.
data Harness = Harness
    { clock :: IORef UTCTime
    , issued :: IORef Int
    -- ^ number of certificates issued so far
    , failing :: IORef (Maybe (IO (Either String ByteString)))
    -- ^ what the issuer does instead of issuing
    , events :: IORef [Event]
    , store :: CertificateStore
    , dir :: FilePath
    }

newHarness :: FilePath -> IO Harness
newHarness path =
    Harness
        <$> newIORef (day 0)
        <*> newIORef 0
        <*> newIORef Nothing
        <*> newIORef []
        <*> newCertificateStore
        <*> pure path

settingsOf :: Harness -> NonEmpty Domain -> ManagerSettings
settingsOf h names =
    (defaultManagerSettings names h.dir)
        { generateKey = genRSAKey 2048
        , onEvent = \e -> modifyIORef' h.events (e :)
        , getTime = readIORef h.clock
        }

-- | Self-signed certificates valid for 90 days from the time of the clock.
issuerOf :: Harness -> Issuer
issuerOf h domain key = do
    instead <- readIORef h.failing
    case instead of
        Just action -> action
        Nothing -> do
            serial <- atomicModifyIORef' h.issued (\n -> (n + 1, n + 1))
            now <- readIORef h.clock
            X509.CertificateChain certs <- selfSignedChain key (toInteger serial) (Text.unpack domain) (now, now `plusDays` 90)
            pure (Right (encodeCertificateChain certs))

managerOf :: Harness -> NonEmpty Domain -> IO CertificateManager
managerOf h names =
    either fail pure =<< newCertificateManager (settingsOf h names) (issuerOf h) h.store

-- | The events since the last call.
takeEvents :: Harness -> IO [Event]
takeEvents h = reverse <$> atomicModifyIORef' h.events ([],)

-- | Serial number of the certificate presented for a server name.
servedSerial :: CertificateStore -> Maybe TLS.HostName -> IO (Maybe Integer)
servedSerial certificates name =
    fmap (serialOf . fst) <$> lookupCredential certificates name

serialOf :: X509.CertificateChain -> Integer
serialOf (X509.CertificateChain certs) =
    case certs of
        (leaf : _) -> X509.certSerial (X509.getCertificate leaf)
        [] -> 0

certificateIsObtainedStoredAndRenewed :: FilePath -> IO ()
certificateIsObtainedStoredAndRenewed path = do
    h <- newHarness path
    mgr <- managerOf h ("a.test" :| [])
    let validity0 = Validity (day 0) (day 90)

    next <- checkCertificates mgr
    count <- readIORef h.issued
    check "a certificate is requested when there is none" (count == 1)
    check "the next check is when the certificate is due for renewal" (next == day 60)
    evs <- takeEvents h
    check "request and success are reported" (evs == [CertificateRequested "a.test", CertificateObtained "a.test" validity0])
    served <- servedSerial h.store (Just "a.test")
    check "the certificate is served for its name" (served == Just 1)
    fallback <- servedSerial h.store Nothing
    check "the certificate is served by default" (fallback == Just 1)
    hasKey <- doesFileExist (path </> "a.test" </> "key.pem")
    check "the key is stored" hasKey
    stored <- decodeCertificateChain <$> ByteString.readFile (path </> "a.test" </> "certificate.pem")
    check "the certificate is stored" (fmap (serialOf . X509.CertificateChain) stored == Right 1)

    writeIORef h.clock (day 59)
    early <- checkCertificates mgr
    count1 <- readIORef h.issued
    check "nothing is requested before the renewal time" (count1 == 1 && early == day 60)

    -- a new run, with an empty store
    restarted <- newHarness path
    writeIORef restarted.clock (day 59)
    manager1 <- managerOf restarted ("a.test" :| [])
    next1 <- checkCertificates manager1
    count2 <- readIORef restarted.issued
    check "the stored certificate is not requested again" (count2 == 0 && next1 == day 60)
    evs1 <- takeEvents restarted
    check "loading is reported" (evs1 == [CertificateLoaded "a.test" validity0])
    served1 <- servedSerial restarted.store (Just "a.test")
    check "the stored certificate is served after a restart" (served1 == Just 1)

    writeIORef h.clock (day 61)
    next2 <- checkCertificates mgr
    count3 <- readIORef h.issued
    check "the certificate is renewed when due" (count3 == 2 && next2 == day 121)
    served2 <- servedSerial h.store (Just "a.test")
    check "the renewed certificate is served" (served2 == Just 2)
    stored2 <- decodeCertificateChain <$> ByteString.readFile (path </> "a.test" </> "certificate.pem")
    check "the renewed certificate is stored" (fmap (serialOf . X509.CertificateChain) stored2 == Right 2)

    -- a new run during the renewal period of the stored certificate
    late <- newHarness path
    writeIORef late.clock (day 125)
    writeIORef late.failing (Just (pure (Left "down")))
    manager2 <- managerOf late ("a.test" :| [])
    _ <- checkCertificates manager2
    served3 <- servedSerial late.store (Just "a.test")
    check "a stored certificate due for renewal is served meanwhile" (served3 == Just 2)

    -- a new run after the end of the stored certificate
    expired <- newHarness path
    writeIORef expired.clock (day 400)
    writeIORef expired.failing (Just (pure (Left "down")))
    manager3 <- managerOf expired ("a.test" :| [])
    _ <- checkCertificates manager3
    served4 <- servedSerial expired.store (Just "a.test")
    check "an expired stored certificate is not served" (served4 == Nothing)

failuresAreRetried :: FilePath -> IO ()
failuresAreRetried path = do
    h <- newHarness path
    mgr <- managerOf h ("a.test" :| [])
    let at seconds = addUTCTime seconds (day 0)

    writeIORef h.failing (Just (pure (Left "no route")))
    next <- checkCertificates mgr
    check "a failure is retried after the first delay" (next == at 120)
    evs <- takeEvents h
    check "the failure is reported" (evs == [CertificateRequested "a.test", CertificateFailed "a.test" "no route" (at 120)])

    writeIORef h.clock (at 60)
    _ <- checkCertificates mgr
    evs1 <- takeEvents h
    check "nothing is requested before the retry time" (null evs1)

    writeIORef h.clock (at 120)
    writeIORef h.failing (Just (throwIO (userError "boom")))
    next1 <- checkCertificates mgr
    check "an exception of the issuer is a failure, retried after a longer delay" (next1 == at (120 + 240))
    evs2 <- takeEvents h
    check "the exception is reported" (map isFailure evs2 == [False, True])

    writeIORef h.clock (at 360)
    writeIORef h.failing (Just (pure (Right "not a certificate")))
    next2 <- checkCertificates mgr
    check "a response without certificate is a failure" (next2 == at (360 + 480))
    hasCert <- doesFileExist (path </> "a.test" </> "certificate.pem")
    check "a response without certificate is not stored" (not hasCert)

    writeIORef h.clock (at 840)
    writeIORef h.failing Nothing
    next3 <- checkCertificates mgr
    served <- servedSerial h.store (Just "a.test")
    check "the certificate is obtained once the issuer works" (served == Just 1 && next3 == day 60)

    -- failures of a renewal
    writeIORef h.clock (day 70)
    writeIORef h.failing (Just (pure (Left "no route")))
    next4 <- checkCertificates mgr
    check "delays start over after a success" (next4 == addUTCTime 120 (day 70))
    served1 <- servedSerial h.store (Just "a.test")
    check "the previous certificate is served while renewals fail" (served1 == Just 1)

    -- a broken event handler
    broken <- newHarness path
    writeIORef broken.clock (day 70)
    let settings = (settingsOf broken ("a.test" :| [])){onEvent = \_ -> throwIO (userError "handler")}
    manager1 <- either fail pure =<< newCertificateManager settings (issuerOf broken) broken.store
    res <- try (checkCertificates manager1)
    check "an exception of the event handler is ignored" (either (\e -> const False (e :: SomeException)) (const True) res)
    count <- readIORef broken.issued
    check "the certificate is renewed despite the event handler" (count == 1)
  where
    isFailure e = case e of
        CertificateFailed _ _ _ -> True
        _ -> False

unusableFilesAreReplaced :: FilePath -> IO ()
unusableFilesAreReplaced path = do
    h <- newHarness path
    mgr <- managerOf h ("a.test" :| [])
    _ <- checkCertificates mgr
    _ <- takeEvents h

    -- the key is replaced behind the back of the manager
    other <- genRSAKey 2048
    writeRSAKeyPEM other (path </> "a.test" </> "key.pem")
    restarted <- newHarness path
    manager1 <- managerOf restarted ("a.test" :| [])
    _ <- checkCertificates manager1
    evs <- takeEvents restarted
    check "a certificate for another key is reported" (take 1 evs == [StoredCertificateUnusable "a.test" "the certificate is not for the stored key"])
    served <- lookupCredential restarted.store (Just "a.test")
    check "a certificate for another key is replaced" (fmap snd served == Just (X509.PrivKeyRSA other))

    ByteString.writeFile (path </> "a.test" </> "key.pem") "not a key"
    broken <- newHarness path
    manager2 <- managerOf broken ("a.test" :| [])
    next <- checkCertificates manager2
    count <- readIORef broken.issued
    check "an unreadable key is a failure, left for the operator" (count == 0 && next == addUTCTime 120 (day 0))
    kept <- ByteString.readFile (path </> "a.test" </> "key.pem")
    check "an unreadable key is not overwritten" (kept == "not a key")

eachDomainHasItsCertificate :: FilePath -> IO ()
eachDomainHasItsCertificate path = do
    h <- newHarness path
    mgr <- managerOf h ("a.test" :| ["B.test"])
    _ <- checkCertificates mgr
    a <- servedSerial h.store (Just "a.test")
    b <- servedSerial h.store (Just "b.test")
    other <- servedSerial h.store (Just "other.test")
    check "each domain gets its certificate" (a == Just 1 && b == Just 2)
    check "the certificate of the first domain is the default one" (other == Just 1)
    hasB <- doesFileExist (path </> "b.test" </> "certificate.pem")
    check "domains are stored in lower case" hasB

redirectsToHttps :: IO ()
redirectsToHttps = do
    let request host = defaultRequest{requestHeaderHost = Just host, requestHeaders = [(hHost, host)], rawPathInfo = "/some/path", rawQueryString = "?q=1"}
    plain <- run (redirectToHttps 443) (request "a.test")
    check "redirects to the same host, path and query" (plain == (status308, Just "https://a.test/some/path?q=1"))
    ported <- run (redirectToHttps 8443) (request "a.test:8080")
    check "redirects to the HTTPS port" (ported == (status308, Just "https://a.test:8443/some/path?q=1"))
    v6 <- run (redirectToHttps 443) (request "[::1]:80")
    check "redirects IPv6 hosts" (v6 == (status308, Just "https://[::1]/some/path?q=1"))
    missing <- run (redirectToHttps 443) defaultRequest
    check "refuses requests without host" (missing == (status400, Nothing))
    weird <- run (redirectToHttps 443) (request "a.test/@evil")
    check "refuses odd hosts" (weird == (status400, Nothing))
  where
    run :: Application -> Request -> IO (Status, Maybe ByteString)
    run app req = do
        result <- newIORef Nothing
        _ <- app req $ \rsp -> do
            writeIORef result (Just (responseStatus rsp, lookup hLocation (responseHeaders rsp)))
            pure (error "unused ResponseReceived")
        maybe (fail "no response") pure =<< readIORef result

{- | Runs 'runAutoHttpsWith' on local ports: the HTTP server answers the
challenges and redirects, the HTTPS server presents the certificates as the
manager gets them.
-}
serversGetTheirCertificate :: FilePath -> IO ()
serversGetTheirCertificate path = do
    h <- newHarness path
    httpPort <- freePort
    httpsPort <- freePort
    challengeSeen <- newIORef Nothing
    let app _ respond = respond $ responseLBS status200 [] "hello"
    let quiet = setOnException (\_ _ -> pure ()) defaultSettings
    let cfg =
            (defaultAutoHttps "http://unused.test/" ("a.test" :| []) [] path)
                { managerSettings = (settingsOf h ("a.test" :| [])){checkInterval = 0.2, getTime = readIORef h.clock}
                , httpSettings = setPort httpPort quiet
                , httpsSettings = setPort httpsPort quiet
                }
    -- an issuer which, as an ACME server does, fetches a challenge first
    let issuer challenges domain key = do
            insertChallenge challenges (Token "tok") (KeyAuthorization "tok.thumbprint")
            fetched <- httpGet httpPort "/.well-known/acme-challenge/tok"
            deleteChallenge challenges (Token "tok")
            writeIORef challengeSeen (Just fetched)
            issuerOf h domain key
    bracket (forkIO $ runAutoHttpsWith issuer cfg app) killThread $ \_ -> do
        first <- eventually (fmap serialOf <$> presented httpsPort "a.test") (== Just 1)
        check "the HTTPS server presents the certificate obtained at startup" first
        seen <- readIORef challengeSeen
        check "the HTTP server answers the challenge" (maybe False (ByteString.isSuffixOf "tok.thumbprint") seen)
        redirected <- httpGet httpPort "/page"
        check "the HTTP server redirects to HTTPS" (("Location: https://a.test:" <> Char8.pack (show httpsPort) <> "/page") `ByteString.isInfixOf` redirected)

        writeIORef h.clock (day 61)
        renewed <- eventually (fmap serialOf <$> presented httpsPort "a.test") (== Just 2)
        check "the running HTTPS server presents the renewed certificate" renewed
  where
    freePort :: IO Port
    freePort = do
        (port, sock) <- openFreePort
        Socket.close sock
        pure port

-- | Polls for up to ten seconds.
eventually :: IO a -> (a -> Bool) -> IO Bool
eventually action ok = go (100 :: Int)
  where
    go 0 = pure False
    go n = do
        x <- action
        if ok x then pure True else threadDelay 100000 >> go (n - 1)

-- | The raw response to a GET on localhost, for the host @a.test@.
httpGet :: Port -> ByteString -> IO ByteString
httpGet port path = do
    res <- timeout 5000000 $ bracket (connect port) Socket.close $ \sock -> do
        SocketBS.sendAll sock ("GET " <> path <> " HTTP/1.0\r\nHost: a.test\r\n\r\n")
        let recvAll acc = do
                chunk <- SocketBS.recv sock 4096
                if ByteString.null chunk then pure acc else recvAll (acc <> chunk)
        recvAll ""
    maybe (fail "no HTTP response") pure res

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

selfSignedChain :: RSA.PrivateKey -> Integer -> String -> (UTCTime, UTCTime) -> IO X509.CertificateChain
selfSignedChain key serial name (start, end) = do
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

    -- test times are at midnight
    midnight :: UTCTime -> DateTime
    midnight (UTCTime d _) =
        let (y, m, dd) = toGregorian d
         in DateTime (Date (fromInteger y) (toEnum (m - 1)) dd) (TimeOfDay 0 0 0 0)

    certificate :: X509.Certificate
    certificate =
        X509.Certificate
            { X509.certVersion = 2
            , X509.certSerial = serial
            , X509.certSignatureAlg = alg
            , X509.certIssuerDN = dn
            , X509.certValidity = (midnight start, midnight end)
            , X509.certSubjectDN = dn
            , X509.certPubKey = X509.PubKeyRSA (RSA.private_pub key)
            , X509.certExtensions = X509.Extensions Nothing
            }

withStateDirectory :: (FilePath -> IO a) -> IO a
withStateDirectory action = do
    tmp <- getTemporaryDirectory
    stamp <- getPOSIXTime
    let path = tmp </> ("acme-not-a-joke-warp-test-" <> show (fromEnum stamp))
    bracket (removePathForcibly path >> createDirectoryIfMissing True path >> pure path) removePathForcibly action

check :: String -> Bool -> IO ()
check name ok = do
    putStrLn $ (if ok then "pass: " else "FAIL: ") <> name
    unless ok exitFailure
