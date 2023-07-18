
module Acme.NotAJoke.Certificate where

import Data.Coerce (coerce)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as ByteString
import Data.Aeson (encode)
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.JWS

-- | The goal of the whole ACME dance is to retrieve such Certificate.
--
-- You should be able to figure out most of the ACME flow by looking how you
-- build a Certificate and pulling all the dependencies.
newtype Certificate = Certificate (Wreq.Response ByteString)
  deriving (Show)

-- | A PEM-file representation of a certificate.
newtype PEM = PEM ByteString

storeCert :: FilePath -> Certificate -> IO ()
storeCert path cert = ByteString.writeFile path (coerce $ readPEM cert)

-- | Lookup a PEM from a certificate.
readPEM :: Certificate -> PEM
readPEM (Certificate rsp) = PEM $ rsp ^. Wreq.responseBody

-- | Retrieves a certificate from an URL.
postGetCertificate :: JWS.JWK -> KID -> Url "certificate" -> Nonce -> IO (Maybe Certificate)
postGetCertificate jwk kid certificateUrl nonce = do
  let opts = Wreq.defaults
               & Wreq.header "Content-Type" .~ ["application/jose+json"]
               & Wreq.header "Accept" .~ ["application/pem-certificate-chain"]
  ebody <- (kidSign jwk ep kid nonce "")
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ Certificate e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "certificate"
    ep = coerce certificateUrl
