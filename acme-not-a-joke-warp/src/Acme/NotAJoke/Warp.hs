{- | Automatic HTTPS for warp, in the spirit of Caddy.

> main :: IO ()
> main =
>     runAutoHttps
>         (defaultAutoHttps letsencryptv2 ("example.com" :| []) ["mailto:certmaster@example.com"] "state")
>         application

'runAutoHttps' runs two servers and a certificate manager:

* an HTTPS server (port 443) running your application, with certificates read
  at each TLS handshake from a 'CertificateStore';
* an HTTP server (port 80) answering the HTTP-01 challenges of the ACME
  server, and redirecting everything else to HTTPS (or running an application
  of yours, see 'httpApplication');
* a "Acme.NotAJoke.Warp.CertificateManager" which obtains the certificates
  when the program starts, stores them on disk, renews them before they
  expire, and puts them in the 'CertificateStore': the running HTTPS server
  presents a new certificate to the next connection, without a restart.

The machine must be reachable from the Internet under each domain name, on
port 80 (for the ACME server) and on the HTTPS port.

Until a first certificate is obtained (a few seconds when all goes well), TLS
handshakes fail: the HTTPS server has nothing to present. A failure to get a
certificate does not stop the servers: it is reported (on stderr unless
'Acme.NotAJoke.Warp.CertificateManager.onEvent' says otherwise) and the
manager tries again later.

To run the servers yourself (e.g., several applications, or another port 80
server), assemble the same parts: 'newChallengeStore' and 'http01Middleware',
'newCertificateStore' and 'liveTlsSettings', 'newCertificateManager' with an
'acmeIssuer' and 'runCertificateManager'. The source of 'runAutoHttpsWith' is
a dozen lines.
-}
module Acme.NotAJoke.Warp (
    -- * automatic HTTPS
    AutoHttps (..),
    defaultAutoHttps,
    runAutoHttps,
    runAutoHttpsWith,

    -- * port 80
    redirectToHttps,

    -- * parts
    module Acme.NotAJoke.Warp.CertificateManager,
    ChallengeStore,
    newChallengeStore,
    http01Middleware,
    CertificateStore,
    newCertificateStore,
    liveTlsSettings,
) where

import Control.Concurrent.Async (waitAny, withAsync)
import Control.Exception (throwIO)
import Control.Monad (void)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Char8 as Char8
import Data.Char (isAlphaNum, isAscii)
import Data.List.NonEmpty (NonEmpty)
import Data.Maybe (fromMaybe)
import Network.HTTP.Types (hContentType, hLocation, status308, status400)
import Network.Wai (Application, rawPathInfo, rawQueryString, requestHeaderHost, responseLBS)
import Network.Wai.Handler.Warp (Port, Settings, defaultSettings, getPort, runSettings, setPort)
import Network.Wai.Handler.WarpTLS (TLSSettings, runTLS)
import System.FilePath ((</>))

import Acme.NotAJoke.Api.Account (Contact)
import Acme.NotAJoke.Api.Endpoint (BaseUrl)
import Acme.NotAJoke.Wai.Http01 (ChallengeStore, http01Middleware, newChallengeStore)
import Acme.NotAJoke.Wai.WarpTLS (CertificateStore, liveTlsSettings, newCertificateStore)
import Acme.NotAJoke.Warp.CertificateManager

-- | What 'runAutoHttps' runs.
data AutoHttps = AutoHttps
    { acmeSettings :: AcmeSettings
    -- ^ the ACME server and account
    , managerSettings :: ManagerSettings
    -- ^ the domains, where certificates are stored and when they are renewed
    , httpSettings :: Settings
    {- ^ warp settings of the HTTP server, defaults to port 80. The ACME
    server only connects to port 80: change the port when something forwards
    port 80 to it.
    -}
    , httpsSettings :: Settings
    -- ^ warp settings of the HTTPS server, defaults to port 443
    , tweakTls :: TLSSettings -> TLSSettings
    {- ^ changes the warp-tls settings, which are the default ones reading
    certificates from the store (see 'liveTlsSettings'). Defaults to 'id'.
    -}
    , httpApplication :: Maybe Application
    {- ^ what the HTTP server runs besides answering challenges, defaults to
    'Nothing': redirect to HTTPS (see 'redirectToHttps')
    -}
    }

{- | Automatic HTTPS for some domains with the certificates of an ACME server
(e.g. 'Acme.NotAJoke.LetsEncrypt.letsencryptv2'), an account with some
contacts (e.g. @["mailto:certmaster\@example.com"]@), and a directory to store
the account key (@account.jwk@), the keys and the certificates.

Using an ACME server means agreeing to its terms of service.
-}
defaultAutoHttps :: BaseUrl -> NonEmpty Domain -> [Contact] -> FilePath -> AutoHttps
defaultAutoHttps url names contactUrls dir =
    AutoHttps
        { acmeSettings = defaultAcmeSettings url (dir </> "account.jwk") contactUrls
        , managerSettings = defaultManagerSettings names dir
        , httpSettings = setPort 80 defaultSettings
        , httpsSettings = setPort 443 defaultSettings
        , tweakTls = id
        , httpApplication = Nothing
        }

{- | Runs an application over HTTPS, with certificates obtained and renewed
from an ACME server.

Runs until one of the two servers stops. Throws what warp throws (e.g., when a
port cannot be bound), and an 'IOError' when a domain is not a plain host
name.
-}
runAutoHttps :: AutoHttps -> Application -> IO ()
runAutoHttps cfg = runAutoHttpsWith (acmeIssuer cfg.acmeSettings) cfg

{- | Same as 'runAutoHttps' with certificates from another issuer, which is
given the store of the challenges answered by the HTTP server. The
'acmeSettings' are ignored.
-}
runAutoHttpsWith :: (ChallengeStore -> Issuer) -> AutoHttps -> Application -> IO ()
runAutoHttpsWith mkIssuer cfg application = do
    challenges <- newChallengeStore
    certificates <- newCertificateStore
    created <- newCertificateManager cfg.managerSettings (mkIssuer challenges) certificates
    certManager <- either (throwIO . userError) pure created
    let plain = fromMaybe (redirectToHttps (getPort cfg.httpsSettings)) cfg.httpApplication
    let http = runSettings cfg.httpSettings (http01Middleware challenges plain)
    let https = runTLS (cfg.tweakTls (liveTlsSettings certificates)) cfg.httpsSettings application
    withAsync http $ \httpServer ->
        withAsync https $ \httpsServer ->
            withAsync (runCertificateManager certManager) $ \renewer ->
                void $ waitAny [httpServer, httpsServer, renewer]

{- | Redirects (308) every request to the same host, path and query over
HTTPS, on the given port.

The host comes from the @Host@ header: requests without one, or with one
which is not a host name or an IP address, get a 400.
-}
redirectToHttps :: Port -> Application
redirectToHttps port req respond =
    case hostName =<< requestHeaderHost req of
        Nothing ->
            respond $ responseLBS status400 [(hContentType, "text/plain")] "bad or missing Host header\n"
        Just host ->
            respond $ responseLBS status308 [(hLocation, location host)] ""
  where
    location host =
        "https://" <> host <> portSuffix <> rawPathInfo req <> rawQueryString req

    portSuffix
        | port == 443 = ""
        | otherwise = Char8.pack (':' : show port)

    -- the host without its port
    hostName hostPort
        | ByteString.null name || not (Char8.all validChar name) = Nothing
        | otherwise = Just name
      where
        name = case Char8.uncons hostPort of
            -- an IPv6 address
            Just ('[', rest) -> "[" <> Char8.takeWhile (/= ']') rest <> "]"
            _ -> Char8.takeWhile (/= ':') hostPort

    validChar c = isAscii c && (isAlphaNum c || c `elem` ("-.:[]" :: String))
