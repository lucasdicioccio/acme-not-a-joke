{-# LANGUAGE DataKinds #-}

-- | The nested JWS of account key rollovers (RFC-8555 section 7.3.5).
module Main (main) where

import Control.Lens (toListOf, view)
import Control.Monad (unless)
import Data.Aeson (FromJSON, Value (..), decode, encode, object, (.=))
import qualified Data.ByteString.Lazy as LByteString
import System.Exit (exitFailure)

import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint (Endpoint (..))
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.KeyChange
import Acme.NotAJoke.Api.Nonce (Nonce (..))
import Acme.NotAJoke.KeyManagement (genRSAKey, jwkFromRSAKey)

main :: IO ()
main = do
    oldJwk <- jwkFromRSAKey <$> genRSAKey 2048
    newJwk <- jwkFromRSAKey <$> genRSAKey 2048
    let ep = Endpoint "https://acme.test/acme/key-change" :: Endpoint "keyChange"
    let kid = KID "https://acme.test/acme/acct/42"

    Right outer <- keyChangeSign oldJwk newJwk kid ep (Nonce "a-nonce")

    -- outer JWS: a regular ACME request signed by the old key
    outerPayload <- verify oldJwk outer
    check "outer JWS, verified with the old key" $ isRight outerPayload
    newVerifiesOuter <- verify newJwk outer
    check "outer JWS, not verified with the new key" $ not (isRight newVerifiesOuter)
    check "outer JWS, url is the keyChange endpoint" $
        map (view acmeURL) (headers outer) == ["https://acme.test/acme/key-change"]
    check "outer JWS, signed with the kid of the account" $
        map (fmap encode . preview' . view acmeAuthBit) (headers outer) == [Just (encode kid)]

    -- inner JWS: the payload of the outer one, signed by the new key
    Right outerBytes <- pure outerPayload
    Just inner <- pure (decodeJWS outerBytes :: Maybe (JWS.FlattenedJWS KeyChangeHeader))
    innerPayload <- verify newJwk inner
    check "inner JWS, verified with the new key" $ isRight innerPayload
    oldVerifiesInner <- verify oldJwk inner
    check "inner JWS, not verified with the old key" $ not (isRight oldVerifiesInner)
    check "inner JWS, url is the keyChange endpoint" $
        map (view keyChangeURL) (headers inner) == ["https://acme.test/acme/key-change"]
    check "inner JWS, jwk is the new public key" $
        map (encode . view keyChangeNewKey) (headers inner) == [encode (publicJWK newJwk)]
    check "inner JWS, has no nonce" $
        isNothing (decodeJWS outerBytes :: Maybe (JWS.FlattenedJWS AcmeHeader))
    check "inner JWS, payload names the account and its old key" $
        fmap decodeValue innerPayload
            == Right
                ( Just $
                    object
                        [ "account" .= kid
                        , "oldKey" .= publicJWK oldJwk
                        ]
                )
  where
    verify :: (JWS.HasJWSHeader h, JWS.HasParams h) => JWK.JWK -> JWS.FlattenedJWS h -> IO (Either JWS.Error LByteString.ByteString)
    verify jwk jws = JWS.runJOSE (maybe (error "no public key") (\pub -> JWS.verifyJWS' pub jws) (view JWK.asPublicKey jwk))

    headers :: JWS.FlattenedJWS h -> [h JWS.Protection]
    headers = toListOf (JWS.signatures . JWS.header)

    decodeJWS :: (FromJSON a) => LByteString.ByteString -> Maybe a
    decodeJWS = decode

    decodeValue :: LByteString.ByteString -> Maybe Value
    decodeValue = decode

    preview' :: Either a b -> Maybe b
    preview' = either (const Nothing) Just

    isRight :: Either a b -> Bool
    isRight = either (const False) (const True)

    isNothing :: Maybe a -> Bool
    isNothing = maybe True (const False)

check :: String -> Bool -> IO ()
check name ok = do
    putStrLn $ (if ok then "ok   " else "FAIL ") <> name
    unless ok exitFailure
