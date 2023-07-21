module Acme.NotAJoke.Api.Authorization where

import Data.Coerce (coerce)
import Data.Text (Text)
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), withText, withObject,ToJSON(..), pairs, encode, (.=), (.:), (.:?), object, decode)
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))
import Data.Time.Clock (UTCTime)

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Field
import Acme.NotAJoke.Api.Nonce
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Challenge

-- RFC-defined authorization statuses.
data AuthorizationStatus
  = AuthorizationPending
  | AuthorizationValid
  | AuthorizationInvalid
  | AuthorizationDeactivated
  | AuthorizationExpired
  | AuthorizationRevoked
  deriving (Show, Eq, Ord)

instance FromJSON AuthorizationStatus where
  parseJSON = withText "AuthorizationStatus" $ \txt ->
                case txt of
                  "pending" -> pure AuthorizationPending
                  "valid" -> pure AuthorizationValid
                  "invalid" -> pure AuthorizationInvalid
                  "deactivated" -> pure AuthorizationDeactivated
                  "expired" -> pure AuthorizationExpired
                  "revoked" -> pure AuthorizationRevoked
                  _     -> fail $ "invalid authorization status:" <> show txt

-- RFC-defined authorization types (only the subset supported in this library).
data AuthorizationType
  = DNSAuthorization
  deriving (Show, Eq, Ord)

instance ToJSON AuthorizationType where
  toEncoding DNSAuthorization = toEncoding ("dns" :: Text)
  toJSON DNSAuthorization = toJSON ("dns" :: Text)
instance FromJSON AuthorizationType where
  parseJSON = withText "Authorizationtype" $ \txt ->
                case txt of
                  "dns" -> pure DNSAuthorization
                  _     -> fail $ "invalid ordertype:" <> show txt

-- | RFC-defined authorization identifiers.
data AuthorizationIdentifier
  = AuthorizationIdentifier
  { type_ :: AuthorizationType
  , value :: Text
  }
  deriving (Show, Eq, Ord)
instance ToJSON AuthorizationIdentifier where
  toEncoding o = pairs ( "type" .= o.type_ <> "value" .= o.value )
  toJSON o = object [ "type" .= o.type_ , "value" .= o.value ]
instance FromJSON AuthorizationIdentifier where
  parseJSON = withObject "AuthorizationIdentifier" $ \o ->
               AuthorizationIdentifier
                 <$> o .: "type"
                 <*> o .: "value"

-- | RFC-defined authorization resource.
data Authorization a
  = Authorization
  { status :: Field a "status" AuthorizationStatus
  , identifier :: Field a "status" AuthorizationIdentifier
  , expires :: Field a "expires" (Maybe UTCTime)
  , challenges :: Field a "challenges" [Challenge "challenge-unspecified"]
  , wildcard :: Field a "wildcard" (Maybe Bool)
  }

newtype AuthorizationInspected = AuthorizationInspected (Wreq.Response ByteString)
  deriving Show

type instance Field "authorization-inspected" "status" x = x
type instance Field "authorization-inspected" "identifier" x = x
type instance Field "authorization-inspected" "expires" x = x
type instance Field "authorization-inspected" "challenges" x = x
type instance Field "authorization-inspected" "wildcard" x = x

instance FromJSON (Authorization "authorization-inspected") where
  parseJSON = withObject "Authorization(inspected)" $ \v ->
                Authorization
                  <$> v .: "status"
                  <*> v .: "identifier"
                  <*> v .: "expires"
                  <*> v .: "challenges"
                  <*> v .:? "wildcard"

-- | Lookup an Authorization.
readAuthorization :: AuthorizationInspected -> Maybe (Authorization "authorization-inspected")
readAuthorization (AuthorizationInspected rsp) = decode $ rsp ^. Wreq.responseBody

-- | Inspects an authorization from its URL.
postGetAuthorization :: JWS.JWK -> KID -> Url "authorization" -> Nonce -> IO (Maybe AuthorizationInspected)
postGetAuthorization jwk kid authUrl nonce = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce "")
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ AuthorizationInspected e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "authorization"
    ep = coerce authUrl
