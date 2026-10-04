{- | A warp server getting its own certificate with an HTTP-01 challenge.

> acme-not-a-joke-wai-example DOMAIN CONTACT-EMAIL STATE-DIRECTORY

The machine must be reachable from the Internet as DOMAIN, on ports 80 and
443. The certificate comes from the staging environment of Let's Encrypt
(browsers do not trust it): replace 'staging_letsencryptv2' with
'letsencryptv2' for a real one.

Files, all in STATE-DIRECTORY:

* @account.jwk@: the ACME account key, created on the first run
* @key.pem@: the private key of the certificate, created on the first run
* @certificate.pem@: the certificate chain, written when a dance succeeds

The CSR is built in memory at each dance, and is not written anywhere.
-}
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Monad (forever, void)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Text as Text
import Network.HTTP.Types (status200)
import Network.Wai (Application, responseLBS)
import Network.Wai.Handler.Warp (defaultSettings, run, setPort)
import Network.Wai.Handler.WarpTLS (runTLS)
import System.Directory (createDirectoryIfMissing, doesFileExist)
import System.Environment (getArgs)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)

import Acme.NotAJoke.Api.Account (fetchAccount1)
import Acme.NotAJoke.Api.Certificate (storeCert)
import Acme.NotAJoke.Api.Endpoint (readProblem)
import Acme.NotAJoke.Api.Order (OrderIdentifier (..), OrderType (..), createOrder)
import Acme.NotAJoke.CertManagement (createCSR)
import Acme.NotAJoke.Dancer (AcmeDancer (..), DanceStep (..))
import Acme.NotAJoke.KeyManagement (loadOrCreateJWKFile, loadOrCreateRSAKeyPEM)
import Acme.NotAJoke.LetsEncrypt (staging_letsencryptv2)
import Acme.NotAJoke.Wai.Http01 (http01Middleware, newChallengeStore, runAcmeDance_http01_wai)
import Acme.NotAJoke.Wai.WarpTLS (installCertificate, liveTlsSettings, loadCredential, newCertificateStore, setCredential)

main :: IO ()
main = do
    args <- getArgs
    case args of
        [domain, email, dir] -> serve domain email dir
        _ -> hPutStrLn stderr "usage: acme-not-a-joke-wai-example DOMAIN CONTACT-EMAIL STATE-DIRECTORY"

serve :: String -> String -> FilePath -> IO ()
serve domain email dir = do
    let accountKeyPath = dir </> "account.jwk"
    let keyPath = dir </> "key.pem"
    let certPath = dir </> "certificate.pem"

    -- keys: loaded from the state directory, created on the first run
    createDirectoryIfMissing True dir
    accountKey <- orDie =<< loadOrCreateJWKFile accountKeyPath
    key <- orDie =<< loadOrCreateRSAKeyPEM keyPath

    -- the two stores, both in memory
    challenges <- newChallengeStore
    certificates <- newCertificateStore

    -- port 80: the ACME server fetches the challenge there
    void $ forkIO $ run 80 (http01Middleware challenges application)
    -- port 443: handshakes fail until the store has a certificate
    void $ forkIO $ runTLS (liveTlsSettings certificates) (setPort 443 defaultSettings) application

    known <- doesFileExist certPath
    if known
        then -- a certificate obtained by a previous run is served right away
            setCredential certificates =<< orDie =<< loadCredential certPath keyPath
        else do
            -- this program is the ACME client: it starts the dance, which
            -- returns once the certificate is installed (or on failure)
            request <- orDie =<< createCSR key (Text.pack domain :| [])
            let handle step = case step of
                    WaitingForValidation n -> threadDelay (n * 1000000)
                    Done _ cert -> do
                        storeCert certPath cert
                        orDie =<< installCertificate certificates key cert
                        putStrLn ("serving the certificate written at " <> certPath)
                    InvalidOrder _ -> hPutStrLn stderr "the ACME server could not validate the challenge"
                    OtherError err -> hPutStrLn stderr (Text.unpack err)
                    AcmeFailure err -> hPutStrLn stderr (show (readProblem err, err))
                    _ -> pure ()
            runAcmeDance_http01_wai challenges $
                AcmeDancer
                    { baseUrl = staging_letsencryptv2
                    , accountJwk = accountKey
                    , -- creates the account when the key has none yet
                      account = fetchAccount1 True False [Text.pack ("mailto:" <> email)]
                    , csr = request
                    , order = createOrder (Nothing, Nothing) [OrderIdentifier DNSOrder (Text.pack domain)]
                    , handleStep = handle
                    }

    forever $ threadDelay 60000000

application :: Application
application _ respond = respond $ responseLBS status200 [] "hello\n"

orDie :: Either String a -> IO a
orDie = either fail pure
