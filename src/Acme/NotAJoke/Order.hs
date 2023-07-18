module Acme.NotAJoke.Order where

import Data.Coerce (coerce)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), withText, withObject,ToJSON(..), pairs, encode, (.=), (.:), (.:?), object, decode)
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))
import Data.Time.Clock (UTCTime)
import Data.Maybe (catMaybes)

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Field
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.JWS
import Acme.NotAJoke.CSR

-- | RFC-defined order statuses.
data OrderStatus
  = OrderPending
  | OrderReady
  | OrderProcessing
  | OrderValid
  | OrderInvalid
  deriving (Show, Eq, Ord)

instance FromJSON OrderStatus where
  parseJSON = withText "OrderStatus" $ \txt ->
                case txt of
                  "pending" -> pure OrderPending
                  "ready" -> pure OrderReady
                  "processing" -> pure OrderProcessing
                  "valid" -> pure OrderValid
                  "invalid" -> pure OrderInvalid
                  _     -> fail $ "invalid order status:" <> show txt

-- | RFC-defined order types (for the subset supported in this library).
data OrderType
  = DNSOrder
  -- ^ Order is about requesting DNS certificates.
  deriving (Show, Eq, Ord)

instance ToJSON OrderType where
  toEncoding DNSOrder = toEncoding ("dns" :: Text)
  toJSON DNSOrder = toJSON ("dns" :: Text)
instance FromJSON OrderType where
  parseJSON = withText "Ordertype" $ \txt ->
                case txt of
                  "dns" -> pure DNSOrder
                  _     -> fail $ "invalid ordertype:" <> show txt

-- | RFC-defined order identifier.
data OrderIdentifier
  = OrderIdentifier
  { type_ :: OrderType
  , value :: Text
  }
  deriving (Show, Eq, Ord)
instance ToJSON OrderIdentifier where
  toEncoding o = pairs ( "type" .= o.type_ <> "value" .= o.value )
  toJSON o = object [ "type" .= o.type_ , "value" .= o.value ]
instance FromJSON OrderIdentifier where
  parseJSON = withObject "OrderIdentifier" $ \o ->
               OrderIdentifier
                 <$> o .: "type"
                 <*> o .: "value"

-- | RFC-defined order structure.
data Order a
  = Order
  { status :: Field a "status" OrderStatus
  , expires :: Field a "expires" UTCTime
  , identifiers :: Field a "identifiers" [OrderIdentifier]
  , notBefore :: Field a "notBefore" (Maybe UTCTime)
  , notAfter :: Field a "notAfter" (Maybe UTCTime)
  , error :: Field a "error" (Maybe Problem)
  , authorizations :: Field a "authorizations" [Url "authorization"]
  , finalize :: Field a "finalize" (Url "finalize-order")
  , certificate :: Field a "certificate" (Url "certificate")
  }

type instance Field "order-create" "status" x = ()
type instance Field "order-create" "expires" x = ()
type instance Field "order-create" "identifiers" x = x
type instance Field "order-create" "notBefore" x = x
type instance Field "order-create" "notAfter" x = x
type instance Field "order-create" "error" x = ()
type instance Field "order-create" "authorizations" x = ()
type instance Field "order-create" "finalize" x = ()
type instance Field "order-create" "certificate" x = ()

newtype OrderCreated = OrderCreated (Wreq.Response ByteString)
  deriving Show

type instance Field "order-created" "status" x = x
type instance Field "order-created" "expires" x = x
type instance Field "order-created" "identifiers" x = x
type instance Field "order-created" "notBefore" x = x
type instance Field "order-created" "notAfter" x = x
type instance Field "order-created" "error" x = x
type instance Field "order-created" "authorizations" x = x
type instance Field "order-created" "finalize" x = x
type instance Field "order-created" "certificate" x = ()

instance FromJSON (Order "order-created") where
  parseJSON = withObject "Order(created)" $ \v ->
                Order
                  <$> v .: "status"
                  <*> v .: "expires"
                  <*> v .: "identifiers"
                  <*> v .:? "notBefore"
                  <*> v .:? "notAfter"
                  <*> v .:? "error"
                  <*> v .: "authorizations"
                  <*> v .: "finalize"
                  <*> pure ()

-- | Prepare a new order.
createOrder :: (Maybe UTCTime, Maybe UTCTime) -> [ OrderIdentifier ] -> Order "order-create"
createOrder (nbefore,nafter) ois =
  Order ()() ois nbefore nafter () () () ()

readOrderUrl :: OrderCreated -> Maybe (Url "order")
readOrderUrl (OrderCreated rsp) = rsp ^? Wreq.responseHeader "location" . to (Url . Encoding.decodeUtf8)

readOrderCreated :: OrderCreated -> Maybe (Order "order-created")
readOrderCreated (OrderCreated rsp) = decode $ rsp ^. Wreq.responseBody

-- | Requests a new order to the server.
postNewOrder :: JWS.JWK -> Endpoint "newOrder" -> KID -> Nonce -> Order "order-create" -> IO (Maybe OrderCreated)
postNewOrder jwk ep kid nonce ord = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce $ encode $ serialized)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ OrderCreated e
    Left err -> do
      print err
      pure Nothing
  where
    serialized = object $ catMaybes
                          [ (\x -> "notBefore" .= x) <$> ord.notBefore
                          , (\x -> "notAfter" .= x) <$> ord.notAfter
                          , Just $ "identifiers" .= ord.identifiers
                          ]

newtype OrderInspected = OrderInspected (Wreq.Response ByteString)
  deriving Show

type instance Field "order-inspected" "status" x = x
type instance Field "order-inspected" "expires" x = x
type instance Field "order-inspected" "identifiers" x = x
type instance Field "order-inspected" "notBefore" x = ()
type instance Field "order-inspected" "notAfter" x = ()
type instance Field "order-inspected" "error" x = x
type instance Field "order-inspected" "authorizations" x = x
type instance Field "order-inspected" "finalize" x = x
type instance Field "order-inspected" "certificate" x = Maybe x

instance FromJSON (Order "order-inspected") where
  parseJSON = withObject "Order(inspected)" $ \v ->
                Order
                  <$> v .: "status"
                  <*> v .: "expires"
                  <*> v .: "identifiers"
                  <*> pure ()
                  <*> pure ()
                  <*> v .:? "error"
                  <*> v .: "authorizations"
                  <*> v .: "finalize"
                  <*> v .:? "certificate"

readOrderInspected :: OrderInspected -> Maybe (Order "order-inspected")
readOrderInspected (OrderInspected rsp) = decode $ rsp ^. Wreq.responseBody

readCertificateUrl :: OrderInspected -> Maybe (Url "certificate")
readCertificateUrl order = 
  certificate =<< readOrderInspected order

-- | Fetches a known order to inspect its status.
postGetOrder :: JWS.JWK -> Url "order" -> KID -> Nonce -> IO (Maybe OrderInspected)
postGetOrder jwk orderurl kid nonce = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce "")
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ OrderInspected e
    Left err -> do
      print err
      pure Nothing
  where
   ep :: Endpoint "order"
   ep = coerce orderurl

-- | RFC-defined finalization request.
-- Consists of a CSR.
data Finalize
  = Finalize
  { csr :: CSR
  }

newtype OrderFinalized = OrderFinalized (Wreq.Response ByteString)
  deriving (Show)

-- todo: specialize status of a finalized order
readOrderFinalized :: OrderFinalized -> Maybe (Order "order-created")
readOrderFinalized (OrderFinalized rsp) = decode $ rsp ^. Wreq.responseBody

-- | Finalize an order after completing a challenge.
postFinalizeOrder :: JWS.JWK -> KID -> Url "finalize-order" -> Finalize -> Nonce -> IO (Maybe OrderFinalized)
postFinalizeOrder jwk kid finalizeurl finalizeobj nonce = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce $ encode $ serialized)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ OrderFinalized e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "finalize-order"
    ep = coerce finalizeurl
    serialized = object $ [ "csr" .= finalizeobj.csr
                          ]
