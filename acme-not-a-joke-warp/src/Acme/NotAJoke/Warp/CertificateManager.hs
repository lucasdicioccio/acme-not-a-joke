{- | Keeps the certificates of a TLS server valid, unattended.

A 'CertificateManager' looks after one certificate per domain name. For each
domain it:

* loads the certificate stored on disk by a previous run, if there is one;
* asks an 'Issuer' for a certificate when there is none, or when the stored one
  is due for renewal (see 'renewAt');
* writes the new certificate on disk, and hands it to a
  'Acme.NotAJoke.Wai.WarpTLS.CertificateStore' so that a running warp-tls
  server presents it to the next connection, without a restart;
* tries again later, with increasing delays, when the 'Issuer' fails (see
  'retryDelay').

'runCertificateManager' is the loop doing so forever, 'checkCertificates' is
a single pass of this loop.

The manager never throws for a failed issuance: errors of the 'Issuer',
whether returned or thrown (e.g., the @HttpException@ of a network failure),
and errors while reading or writing files are reported to 'onEvent' and the
certificate is tried again later. Meanwhile, the server keeps presenting the
certificate it has.

= Where things are stored

Everything is under the 'stateDirectory':

* @{domain}\/key.pem@: the private key of the certificate, created on the
  first run (see 'generateKey') and reused for renewals
* @{domain}\/certificate.pem@: the certificate chain, leaf certificate first

These are the formats that warp-tls, nginx, haproxy etc. read. Files are
replaced atomically (written aside, then renamed). The directory holds private
keys: restrict who can read it.

The ACME account key of 'acmeIssuer' is stored where 'accountKeyPath' says.
-}
module Acme.NotAJoke.Warp.CertificateManager (
    -- * manager
    CertificateManager,
    newCertificateManager,
    runCertificateManager,
    checkCertificates,

    -- * settings
    Domain,
    ManagerSettings (..),
    defaultManagerSettings,
    keyPath,
    certificatePath,

    -- * renewal
    Validity (..),
    renewAfterTwoThirds,
    renewBefore,
    exponentialRetry,

    -- * events
    Event (..),
    showEvent,
    logEvent,

    -- * issuers
    Issuer,
    AcmeSettings (..),
    defaultAcmeSettings,
    acmeIssuer,
) where

import Control.Concurrent (threadDelay)
import Control.Exception (Exception, SomeAsyncException (..), SomeException, catch, displayException, fromException, throwIO)
import Control.Monad (forever, unless, void, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT)
import qualified Crypto.PubKey.RSA as RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LByteString
import Data.Char (isAsciiLower, isDigit)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (NominalDiffTime, UTCTime (..), addUTCTime, diffUTCTime, getCurrentTime)
import qualified Data.X509 as X509
import Network.TLS (Credential)
import System.Directory (createDirectoryIfMissing, doesFileExist, renameFile)
import System.FilePath (takeDirectory, (<.>), (</>))
import System.IO (hPutStrLn, stderr)
import qualified Time.Types as Hourglass

import Acme.NotAJoke.Api.Account (Contact, fetchAccount1)
import Acme.NotAJoke.Api.Certificate (PEM (..), readPEM)
import Acme.NotAJoke.Api.Endpoint (AcmeError, BaseUrl, problemDetail, readProblem)
import Acme.NotAJoke.Api.Order (OrderIdentifier (..), OrderType (..), createOrder)
import Acme.NotAJoke.CertManagement (createCSR, decodeCertificateChain)
import Acme.NotAJoke.Dancer (AcmeDancer (..), DanceStep (..))
import Acme.NotAJoke.KeyManagement (encodeRSAKeyPEM, genRSAKey4096, loadOrCreateJWKFile, loadRSAKeyPEM)
import Acme.NotAJoke.Wai.Http01 (ChallengeStore, runAcmeDance_http01_wai)
import Acme.NotAJoke.Wai.WarpTLS (CertificateStore, setCredential, setCredentialFor)

{- | A DNS name, in ASCII form (i.e., punycode-encoded for internationalized
names). Wildcards are not supported.
-}
type Domain = Text

{- | Gets a certificate for a domain and the private key of the certificate.

Returns the content of a PEM file: the certificate chain, leaf certificate
first. See 'acmeIssuer' for the ACME one.
-}
type Issuer = Domain -> RSA.PrivateKey -> IO (Either String ByteString)

-- | The period during which a certificate is valid.
data Validity = Validity
    { notBefore :: UTCTime
    , notAfter :: UTCTime
    }
    deriving (Show, Eq)

-- | What a manager does and when.
data ManagerSettings = ManagerSettings
    { domains :: NonEmpty Domain
    {- ^ the names to get a certificate for: one certificate per name. The
    certificate of the first name also is the default one, presented to
    clients asking for another name (or for none).
    -}
    , stateDirectory :: FilePath
    -- ^ where keys and certificates are stored, created if missing
    , renewAt :: Validity -> UTCTime
    -- ^ when to renew a certificate, defaults to 'renewAfterTwoThirds'
    , retryDelay :: Int -> NominalDiffTime
    {- ^ how long to wait after the n-th failure in a row (starting at 1),
    defaults to 'exponentialRetry'
    -}
    , checkInterval :: NominalDiffTime
    {- ^ the longest 'runCertificateManager' sleeps between two looks at the
    clock, defaults to one hour
    -}
    , generateKey :: IO RSA.PrivateKey
    {- ^ generates the private key of a certificate, defaults to
    'genRSAKey4096'
    -}
    , onEvent :: Event -> IO ()
    -- ^ called for each 'Event', defaults to 'logEvent'
    , getTime :: IO UTCTime
    -- ^ the clock, defaults to 'getCurrentTime'
    }

-- | Settings with the defaults documented in 'ManagerSettings'.
defaultManagerSettings :: NonEmpty Domain -> FilePath -> ManagerSettings
defaultManagerSettings names dir =
    ManagerSettings
        { domains = names
        , stateDirectory = dir
        , renewAt = renewAfterTwoThirds
        , retryDelay = exponentialRetry
        , checkInterval = 3600
        , generateKey = genRSAKey4096
        , onEvent = logEvent
        , getTime = getCurrentTime
        }

{- | Renews when two thirds of the validity period have elapsed (e.g., 30 days
before the end for a certificate valid for 90 days).
-}
renewAfterTwoThirds :: Validity -> UTCTime
renewAfterTwoThirds validity =
    addUTCTime (2 * diffUTCTime validity.notAfter validity.notBefore / 3) validity.notBefore

-- | Renews a fixed duration before the end of the validity period.
renewBefore :: NominalDiffTime -> Validity -> UTCTime
renewBefore margin validity = addUTCTime (negate margin) validity.notAfter

{- | Two minutes after the first failure, then twice as long after each
failure, up to six hours.

ACME providers limit the number of failed validations (e.g., five per hour
and per name at Let's Encrypt): do not retry much faster.
-}
exponentialRetry :: Int -> NominalDiffTime
exponentialRetry n = min (6 * 3600) (120 * 2 ^ (max 0 (min 16 (n - 1))))

-- | What happens to the certificates of a manager.
data Event
    = -- | a certificate stored by a previous run is served
      CertificateLoaded Domain Validity
    | -- | the stored key or certificate cannot be used, with the reason: a new certificate is requested
      StoredCertificateUnusable Domain String
    | -- | the issuer is asked for a certificate
      CertificateRequested Domain
    | -- | a new certificate is stored and served
      CertificateObtained Domain Validity
    | -- | no certificate, with the reason and the time of the next attempt
      CertificateFailed Domain String UTCTime
    deriving (Show, Eq)

-- | A line of log for an event.
showEvent :: Event -> String
showEvent event =
    case event of
        CertificateLoaded domain validity ->
            line domain ("serving the stored certificate, valid until " <> show validity.notAfter)
        StoredCertificateUnusable domain reason ->
            line domain ("cannot use the stored certificate: " <> reason)
        CertificateRequested domain ->
            line domain "requesting a certificate"
        CertificateObtained domain validity ->
            line domain ("serving a new certificate, valid until " <> show validity.notAfter)
        CertificateFailed domain reason next ->
            line domain ("no certificate, next attempt at " <> show next <> ": " <> reason)
  where
    line domain msg = "acme-not-a-joke-warp: " <> Text.unpack domain <> ": " <> msg

-- | Prints the event on stderr.
logEvent :: Event -> IO ()
logEvent = hPutStrLn stderr . showEvent

-- | Path of the private key of the certificate of a domain.
keyPath :: ManagerSettings -> Domain -> FilePath
keyPath cfg domain = cfg.stateDirectory </> Text.unpack domain </> "key.pem"

-- | Path of the certificate chain of a domain.
certificatePath :: ManagerSettings -> Domain -> FilePath
certificatePath cfg domain = cfg.stateDirectory </> Text.unpack domain </> "certificate.pem"

data DomainState = DomainState
    { due :: UTCTime
    -- ^ nothing to do before this time
    , failures :: Int
    -- ^ failures in a row
    }

-- | See 'newCertificateManager'.
data CertificateManager = CertificateManager
    { settings :: ManagerSettings
    , issuer :: Issuer
    , store :: CertificateStore
    , states :: IORef (Map Domain DomainState)
    }

{- | Creates a manager getting its certificates from an issuer and handing
them to a store.

Nothing happens until 'runCertificateManager' or 'checkCertificates' is
called. The store is the one given to
'Acme.NotAJoke.Wai.WarpTLS.liveTlsSettings'.

Domain names are lower-cased. Fails on names which are not plain host names
(they are used as directory names, and wildcards cannot be validated with
HTTP-01).
-}
newCertificateManager :: ManagerSettings -> Issuer -> CertificateStore -> IO (Either String CertificateManager)
newCertificateManager cfg getCertificate certificates =
    case traverse hostName (NonEmpty.nub (NonEmpty.map Text.toLower cfg.domains)) of
        Left err -> pure (Left err)
        Right names -> do
            ref <- newIORef Map.empty
            pure $ Right $ CertificateManager cfg{domains = names} getCertificate certificates ref
  where
    hostName :: Domain -> Either String Domain
    hostName name
        | validDomain name = Right name
        | otherwise = Left ("not a host name: " <> show name)

validDomain :: Domain -> Bool
validDomain name =
    not (Text.null name)
        && Text.length name <= 253
        && all validLabel (Text.splitOn "." name)
  where
    validLabel label =
        not (Text.null label)
            && Text.all (\c -> isAsciiLower c || isDigit c || c == '-') label

{- | Checks the certificates forever: sleeps until the next certificate is due
(for renewal, or for another attempt after a failure), up to 'checkInterval'.

Run it in its own thread, next to the servers.
-}
runCertificateManager :: CertificateManager -> IO a
runCertificateManager manager = forever $ do
    next <- checkCertificates manager
    now <- manager.settings.getTime
    let wait = max 1 (min manager.settings.checkInterval (diffUTCTime next now))
    threadDelay (ceiling (wait * 1000000))

{- | Checks every domain once: loads, obtains or renews the certificates which
are due, and leaves the other ones alone.

Returns when to call it again: the earliest time at which a certificate is due.
Failures are reported to 'onEvent' rather than thrown.
-}
checkCertificates :: CertificateManager -> IO UTCTime
checkCertificates manager = do
    let first :| others = manager.settings.domains
    dues <- (:|) <$> checkDomain manager True first <*> traverse (checkDomain manager False) others
    pure (minimum dues)

checkDomain :: CertificateManager -> Bool -> Domain -> IO UTCTime
checkDomain manager isDefault domain = do
    now <- manager.settings.getTime
    known <- Map.lookup domain <$> readIORef manager.states
    case known of
        Just st | st.due > now -> pure st.due
        _ -> do
            outcome <- guarded (ensureCertificate manager isDefault domain now)
            let st = nextState now (maybe 0 (.failures) known) outcome
            atomicModifyIORef' manager.states (\m -> (Map.insert domain st m, ()))
            case outcome of
                Left reason -> emit manager (CertificateFailed domain reason st.due)
                Right _ -> pure ()
            pure st.due
  where
    nextState :: UTCTime -> Int -> Either String Validity -> DomainState
    nextState now failed outcome =
        case outcome of
            Left _ -> DomainState (addUTCTime (retryAfter (failed + 1)) now) (failed + 1)
            -- a certificate which already is due for renewal is not requested
            -- again right away
            Right validity -> DomainState (max (manager.settings.renewAt validity) (addUTCTime (retryAfter 1) now)) 0

    retryAfter :: Int -> NominalDiffTime
    retryAfter = max 1 . manager.settings.retryDelay

{- | Serves a certificate which is not due for renewal: the stored one, or a
new one from the issuer.
-}
ensureCertificate :: CertificateManager -> Bool -> Domain -> UTCTime -> IO (Either String Validity)
ensureCertificate manager isDefault domain now = runExceptT $ do
    liftIO $ createDirectoryIfMissing True (takeDirectory keyFile)
    key <- ExceptT $ loadOrCreateKey manager.settings.generateKey keyFile
    stored <- liftIO $ loadStored key certFile
    case stored of
        Right (Just (cred, validity))
            | now < manager.settings.renewAt validity -> liftIO $ do
                install cred
                emit manager (CertificateLoaded domain validity)
                pure validity
            | now < validity.notAfter -> do
                -- still good to serve while the new one is requested
                liftIO $ install cred
                request key
        Right _ -> request key
        Left reason -> do
            liftIO $ emit manager (StoredCertificateUnusable domain reason)
            request key
  where
    keyFile = keyPath manager.settings domain
    certFile = certificatePath manager.settings domain

    install :: Credential -> IO ()
    install cred = do
        setCredentialFor manager.store (Text.unpack domain) cred
        when isDefault $ setCredential manager.store cred

    request :: RSA.PrivateKey -> ExceptT String IO Validity
    request key = do
        liftIO $ emit manager (CertificateRequested domain)
        pem <- ExceptT $ manager.issuer domain key
        (cred, validity) <- ExceptT $ pure $ readCredential key pem
        liftIO $ do
            writeFileAtomic certFile pem
            install cred
            emit manager (CertificateObtained domain validity)
        pure validity

loadOrCreateKey :: IO RSA.PrivateKey -> FilePath -> IO (Either String RSA.PrivateKey)
loadOrCreateKey generate path = do
    exists <- doesFileExist path
    if exists
        then loadRSAKeyPEM path
        else do
            key <- generate
            writeFileAtomic path (encodeRSAKeyPEM key)
            pure (Right key)

-- | The stored certificate, if there is one.
loadStored :: RSA.PrivateKey -> FilePath -> IO (Either String (Maybe (Credential, Validity)))
loadStored key path = do
    exists <- doesFileExist path
    if exists
        then fmap Just . readCredential key <$> ByteString.readFile path
        else pure (Right Nothing)

-- | Reads a certificate chain (PEM), which must be for the given key.
readCredential :: RSA.PrivateKey -> ByteString -> Either String (Credential, Validity)
readCredential key pem = do
    chain <- decodeCertificateChain pem
    case chain of
        [] -> Left "no certificate in the PEM content"
        (leaf : _) -> do
            let cert = X509.getCertificate leaf
            unless (X509.certPubKey cert == X509.PubKeyRSA (RSA.private_pub key)) $
                Left "the certificate is not for the stored key"
            let (start, end) = X509.certValidity cert
            pure ((X509.CertificateChain chain, X509.PrivKeyRSA key), Validity (toUTCTime start) (toUTCTime end))

toUTCTime :: Hourglass.DateTime -> UTCTime
toUTCTime (Hourglass.DateTime (Hourglass.Date year month day) (Hourglass.TimeOfDay hours minutes seconds _)) =
    UTCTime
        (fromGregorian (fromIntegral year) (fromEnum month + 1) day)
        (fromIntegral hours * 3600 + fromIntegral minutes * 60 + fromIntegral seconds)

-- | Writes aside then renames, so that readers never see half a file.
writeFileAtomic :: FilePath -> ByteString -> IO ()
writeFileAtomic path bytes = do
    let tmp = path <.> "tmp"
    ByteString.writeFile tmp bytes
    renameFile tmp path

-- | Calls the event handler, which must not break the manager.
emit :: CertificateManager -> Event -> IO ()
emit manager event =
    void $ guarded (Right <$> manager.settings.onEvent event)

{- | Turns synchronous exceptions into errors. Asynchronous ones (e.g., the
thread being killed) are thrown again.
-}
guarded :: IO (Either String a) -> IO (Either String a)
guarded action = action `catch` handler
  where
    handler :: SomeException -> IO (Either String a)
    handler e =
        case fromException e of
            Just (SomeAsyncException _) -> throwIO e
            Nothing -> pure (Left (displayException e))

-- | How to get certificates from an ACME server.
data AcmeSettings = AcmeSettings
    { acmeUrl :: BaseUrl
    -- ^ the ACME server, e.g. 'Acme.NotAJoke.LetsEncrypt.letsencryptv2'
    , accountKeyPath :: FilePath
    {- ^ where the account key (a JWK) is stored. The key is created on the
    first run, and so is the account.
    -}
    , contacts :: [Contact]
    -- ^ contacts of the account, e.g. @["mailto:certmaster\@example.com"]@
    , pollDelay :: Int -> Int
    {- ^ how long to wait (in microseconds) before the n-th poll of an order
    (starting at 0), defaults to n seconds capped at ten seconds
    -}
    , maxPolls :: Int
    -- ^ how many times an order is polled before giving up, defaults to 60
    }

{- | Settings with the defaults documented in 'AcmeSettings'.

Using an ACME server means agreeing to its terms of service: 'acmeIssuer'
says so when it creates the account.
-}
defaultAcmeSettings :: BaseUrl -> FilePath -> [Contact] -> AcmeSettings
defaultAcmeSettings url path contactUrls =
    AcmeSettings
        { acmeUrl = url
        , accountKeyPath = path
        , contacts = contactUrls
        , pollDelay = \n -> 1000000 * min 10 n
        , maxPolls = 60
        }

{- | Gets certificates from an ACME server with HTTP-01 challenges.

The challenges are served from the store by
'Acme.NotAJoke.Wai.Http01.http01Middleware', which must be running on port 80
of the domain and reachable by the ACME server.

Each call is a whole ACME dance, with a new CSR built in memory.
-}
acmeIssuer :: AcmeSettings -> ChallengeStore -> Issuer
acmeIssuer acme challenges domain key = runExceptT $ do
    liftIO $ createDirectoryIfMissing True (takeDirectory acme.accountKeyPath)
    accountKey <- ExceptT $ loadOrCreateJWKFile acme.accountKeyPath
    request <- ExceptT $ createCSR key (domain :| [])
    result <- liftIO $ newIORef (Left "the ACME dance stopped without a certificate")
    let handle step =
            case step of
                WaitingForValidation n
                    | n >= acme.maxPolls -> writeIORef result (Left "the order still is pending") >> throwIO PollingTimeout
                    | otherwise -> threadDelay (acme.pollDelay n)
                Done _ cert -> writeIORef result (Right (pemBytes (readPEM cert)))
                InvalidOrder _ -> writeIORef result (Left "the ACME server could not validate the challenge")
                OtherError err -> writeIORef result (Left (Text.unpack err))
                AcmeFailure err -> writeIORef result (Left (showAcmeError err))
                _ -> pure ()
    let dancer =
            AcmeDancer
                { baseUrl = acme.acmeUrl
                , accountJwk = accountKey
                , -- creates the account when the key has none yet
                  account = fetchAccount1 True False acme.contacts
                , csr = request
                , order = createOrder (Nothing, Nothing) [OrderIdentifier DNSOrder domain]
                , handleStep = handle
                }
    liftIO $ runAcmeDance_http01_wai challenges dancer `catch` \PollingTimeout -> pure ()
    ExceptT $ readIORef result
  where
    pemBytes (PEM bytes) = LByteString.toStrict bytes

-- | Stops a dance whose order never leaves the pending state.
data PollingTimeout = PollingTimeout
    deriving (Show)

instance Exception PollingTimeout

showAcmeError :: AcmeError -> String
showAcmeError err =
    case problemDetail =<< readProblem err of
        Just detail -> "the ACME server rejected a request: " <> Text.unpack detail
        Nothing -> show err
