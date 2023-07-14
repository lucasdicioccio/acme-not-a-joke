
module Acme.NotAJoke.Certificate where

import Data.Coerce (coerce)
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (encode)
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.JWS

newtype Certificate = Certificate (Wreq.Response ByteString)
  deriving (Show)

newtype PEM = PEM ByteString

readPEM :: Certificate -> PEM
readPEM (Certificate rsp) = PEM $ rsp ^. Wreq.responseBody

postGetCertificate :: JWS.JWK -> KID -> Nonce -> Url "certificate" -> IO (Maybe Certificate)
postGetCertificate jwk kid nonce certificateUrl = do
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

