module Acme.NotAJoke.KeyManagement where

import qualified Data.ByteString.Lazy as LBS
import Data.Aeson (decode, encode)

import qualified Crypto.JOSE.JWK as JWK

-- | Generates and RSA-4096 bits key.
genJWKrsa4096 :: IO JWK.JWK
genJWKrsa4096 = JWK.genJWK (JWK.RSAGenParam (4096 `div` 8))

-- | Loads a JWK from a file.
loadJWKFile :: FilePath -> IO (Maybe JWK.JWK)
loadJWKFile = fmap decode . LBS.readFile

-- | Loads a JWK from a file.
writeJWKFile :: JWK.JWK -> FilePath -> IO ()
writeJWKFile jwk path = LBS.writeFile path (encode jwk)
