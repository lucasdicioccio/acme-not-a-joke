{- | A warp server with automatic HTTPS.

> acme-not-a-joke-warp-example DOMAIN CONTACT-EMAIL STATE-DIRECTORY

The machine must be reachable from the Internet as DOMAIN, on ports 80 and
443. The certificate comes from the staging environment of Let's Encrypt
(browsers do not trust it): replace 'staging_letsencryptv2' with
'letsencryptv2' for a real one.

Files, all in STATE-DIRECTORY:

* @account.jwk@: the ACME account key, created on the first run
* @DOMAIN\/key.pem@: the private key of the certificate, created on the first run
* @DOMAIN\/certificate.pem@: the certificate chain, written at each renewal

The program can be stopped and started again: it serves the stored certificate
and only asks for a new one when it is due for renewal.
-}
module Main (main) where

import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Text as Text
import Network.HTTP.Types (status200)
import Network.Wai (Application, responseLBS)
import System.Environment (getArgs)
import System.IO (hPutStrLn, stderr)

import Acme.NotAJoke.LetsEncrypt (staging_letsencryptv2)
import Acme.NotAJoke.Warp (defaultAutoHttps, runAutoHttps)

main :: IO ()
main = do
    args <- getArgs
    case args of
        [domain, email, dir] ->
            runAutoHttps
                (defaultAutoHttps staging_letsencryptv2 (Text.pack domain :| []) [Text.pack ("mailto:" <> email)] dir)
                application
        _ -> hPutStrLn stderr "usage: acme-not-a-joke-warp-example DOMAIN CONTACT-EMAIL STATE-DIRECTORY"

application :: Application
application _ respond = respond $ responseLBS status200 [] "hello\n"
