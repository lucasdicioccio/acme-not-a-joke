{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Acme.NotAJoke.JWS where

import Control.Applicative ((<|>))
import Control.Exception (Exception, throwIO)
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), ToJSON(..), (.=), Value(..))
import Control.Lens hiding ((.=))

import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Nonce


-- JWS

newtype PublicJWK = PublicJWK JWK.JWK
  deriving (Show, FromJSON, ToJSON)

publicJWK :: JWK.JWK -> Maybe PublicJWK
publicJWK = coerce . view JWK.asPublicKey

newtype KID = KID Text
  deriving (Show, FromJSON, ToJSON)

data AcmeHeader p
  = AcmeHeader
  { _jwsHeader :: JWS.JWSHeader p
  , _acmeURL :: RawEndpoint
  , _acmeNonce :: Nonce
  , _acmeAuthBit :: Either PublicJWK KID
  }

acmeJwsHeader :: Lens' (AcmeHeader p) (JWS.JWSHeader p)
acmeJwsHeader f s@(AcmeHeader { _jwsHeader = a}) =
  fmap (\a' -> s { _jwsHeader = a'}) (f a)

acmeNonce :: Lens' (AcmeHeader p) Nonce
acmeNonce f s@(AcmeHeader { _acmeNonce = a}) =
  fmap (\a' -> s { _acmeNonce = a'}) (f a)

acmeURL :: Lens' (AcmeHeader p) RawEndpoint
acmeURL f s@(AcmeHeader { _acmeURL = a}) =
  fmap (\a' -> s { _acmeURL = a'}) (f a)

acmeAuthBit :: Lens' (AcmeHeader p) (Either PublicJWK KID)
acmeAuthBit f s@(AcmeHeader { _acmeAuthBit = a}) =
  fmap (\a' -> s { _acmeAuthBit = a'}) (f a)

instance JWS.HasJWSHeader AcmeHeader where
  jwsHeader = acmeJwsHeader

instance JWS.HasParams AcmeHeader where
  parseParamsFor proxy hp hu = AcmeHeader
    <$> JWS.parseParamsFor proxy hp hu
    <*> JWS.headerRequiredProtected "url" hp hu
    <*> JWS.headerRequiredProtected "nonce" hp hu
    <*> jwkOrKid
    where
      jwkOrKid = (JWS.headerRequiredProtected "jwk" hp hu) <|> (JWS.headerRequiredProtected "kid" hp hu)
  params h =
    [ (True, "nonce" .= view acmeNonce h)
    , (True, "url" .= view acmeURL h)
    ]
    <> JWS.params (view acmeJwsHeader h)
    <> view (acmeAuthBit . _Left . to (\jwk -> [(True, "jwk" .= jwk)])) h
    <> view (acmeAuthBit . _Right . to (\kid -> [(True, "kid" .= kid)])) h
  extensions = const ["nonce", "url", "jwk", "kid"]

data NoPublicKeyInJWK = NoPublicKeyInJWK
  deriving (Show)
instance Exception NoPublicKeyInJWK

jwkSign :: JWS.JWK -> Endpoint a -> Nonce -> ByteString -> IO (Either JWS.Error (JWS.FlattenedJWS AcmeHeader))
jwkSign jwk ep nonce payload = do
  jwk2 <- maybe (throwIO NoPublicKeyInJWK) pure $ publicJWK jwk
  JWS.runJOSE $ do
    -- alg <- JWS.bestJWSAlg jwk
    let alg = JWS.RS256
    let header = AcmeHeader (JWS.newJWSHeader (JWS.Protected, alg)) (raw ep) nonce (Left jwk2)
    JWS.signJWS payload (pure (header, jwk))

kidSign :: JWS.JWK -> Endpoint a -> KID -> Nonce -> ByteString -> IO (Either JWS.Error (JWS.FlattenedJWS AcmeHeader))
kidSign jwk ep kid nonce payload = JWS.runJOSE $ do
  -- alg <- JWS.bestJWSAlg jwk
  let alg = JWS.RS256
  let header = AcmeHeader (JWS.newJWSHeader (JWS.Protected, alg)) (raw ep) nonce (Right kid)
  JWS.signJWS payload (pure (header, jwk))

newtype EmptyObject = EmptyObject Value
  deriving (Show, FromJSON, ToJSON)

emptyObject :: EmptyObject
emptyObject = EmptyObject (Object mempty)

newtype EmptyText = EmptyText Value
  deriving (Show, FromJSON, ToJSON)

emptyText :: EmptyText
emptyText = EmptyText (String mempty)

