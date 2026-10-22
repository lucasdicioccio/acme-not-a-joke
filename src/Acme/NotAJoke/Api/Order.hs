{- | ACME orders (RFC-8555 sections 7.1.3 and 7.4).

An order asks for a certificate for a list of identifiers (domain names,
possibly wildcards such as @*.example.com@). Its life goes:

1. the client creates it ('createOrder', 'postNewOrder'), the server replies
   with the order URL (see 'readOrderUrl') and one authorization URL per
   identifier (see 'readOrderCreated' and "Acme.NotAJoke.Api.Authorization")
2. the order is @pending@ until the client has validated all the
   authorizations (see "Acme.NotAJoke.Api.Challenge"), then @ready@
3. the client sends its CSR to the @finalize@ URL ('postFinalizeOrder'), the
   order goes @processing@ then @valid@
4. the order of 'postGetOrder' then has a @certificate@ URL (see
   'readCertificateUrl'), from which to download the certificate (see
   "Acme.NotAJoke.Api.Certificate")

An order which fails at any point goes @invalid@, with a problem document in
its @error@ field.

'Order' has three states (see "Acme.NotAJoke.Api.Field"):
@\"order-create\"@, @\"order-created\"@ and @\"order-inspected\"@.
-}
module Acme.NotAJoke.Api.Order where

import Data.Aeson (FromJSON (..), ToJSON (..), decode, encode, object, pairs, withObject, withText, (.:), (.:?), (.=))
import Data.Coerce (coerce)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.Time.Clock (UTCTime)
import qualified Network.HTTP.Client as HTTP

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Field
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Nonce

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
            _ -> fail $ "invalid order status:" <> show txt

-- | RFC-defined order types (for the subset supported in this library).
data OrderType
    = -- | Order is about requesting DNS certificates.
      DNSOrder
    deriving (Show, Eq, Ord)

instance ToJSON OrderType where
    toEncoding DNSOrder = toEncoding ("dns" :: Text)
    toJSON DNSOrder = toJSON ("dns" :: Text)
instance FromJSON OrderType where
    parseJSON = withText "Ordertype" $ \txt ->
        case txt of
            "dns" -> pure DNSOrder
            _ -> fail $ "invalid ordertype:" <> show txt

-- | RFC-defined order identifier.
data OrderIdentifier
    = OrderIdentifier
    { type_ :: OrderType
    , value :: Text
    }
    deriving (Show, Eq, Ord)

instance ToJSON OrderIdentifier where
    toEncoding o = pairs ("type" .= o.type_ <> "value" .= o.value)
    toJSON o = object ["type" .= o.type_, "value" .= o.value]
instance FromJSON OrderIdentifier where
    parseJSON = withObject "OrderIdentifier" $ \o ->
        OrderIdentifier
            <$> o .: "type"
            <*> o .: "value"

{- | RFC-defined order structure, the set of fields depending on the state @a@
(@\"order-create\"@, @\"order-created\"@ or @\"order-inspected\"@).
-}
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

-- | The response of the server to 'postNewOrder'.
newtype OrderCreated = OrderCreated Response
    deriving (Show)

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

{- | Prepare a new order, with optional @notBefore@ and @notAfter@ dates for
the certificate (servers such as Let's Encrypt do not support them, pass
@(Nothing, Nothing)@) and the identifiers the certificate is for.
-}
createOrder :: (Maybe UTCTime, Maybe UTCTime) -> [OrderIdentifier] -> Order "order-create"
createOrder (nbefore, nafter) ois =
    Order () () ois nbefore nafter () () () ()

-- | Lookup the URL of a new order (to poll it with 'postGetOrder').
readOrderUrl :: OrderCreated -> Maybe (Url "order")
readOrderUrl (OrderCreated rsp) = Url . Encoding.decodeUtf8 <$> responseHeader "location" rsp

-- | Lookup the order the server created.
readOrderCreated :: OrderCreated -> Maybe (Order "order-created")
readOrderCreated (OrderCreated rsp) = decode $ HTTP.responseBody rsp

-- | Requests a new order to the server.
postNewOrder :: JWS.JWK -> Endpoint "newOrder" -> KID -> Nonce -> Order "order-create" -> IO (Either AcmeError OrderCreated)
postNewOrder jwk ep kid nonce ord = do
    ebody <- (kidSign jwk ep kid nonce $ encode $ serialized)
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap OrderCreated e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    serialized =
        object $
            catMaybes
                [ (\x -> "notBefore" .= x) <$> ord.notBefore
                , (\x -> "notAfter" .= x) <$> ord.notAfter
                , Just $ "identifiers" .= ord.identifiers
                ]

-- | The response of the server to 'postGetOrder'.
newtype OrderInspected = OrderInspected Response
    deriving (Show)

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

-- | Lookup the order in a response to 'postGetOrder'.
readOrderInspected :: OrderInspected -> Maybe (Order "order-inspected")
readOrderInspected (OrderInspected rsp) = decode $ HTTP.responseBody rsp

-- | Lookup the URL of the certificate of a valid order.
readCertificateUrl :: OrderInspected -> Maybe (Url "certificate")
readCertificateUrl order =
    certificate =<< readOrderInspected order

-- | Fetches a known order to inspect its status.
postGetOrder :: JWS.JWK -> Url "order" -> KID -> Nonce -> IO (Either AcmeError OrderInspected)
postGetOrder jwk orderurl kid nonce = do
    ebody <- (kidSign jwk ep kid nonce "")
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap OrderInspected e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    ep :: Endpoint "order"
    ep = coerce orderurl

{- | RFC-defined finalization request.
Consists of a CSR.
-}
data Finalize
    = Finalize
    { csr :: CSR
    }

-- | The response of the server to 'postFinalizeOrder'.
newtype OrderFinalized = OrderFinalized Response
    deriving (Show)

-- todo: specialize status of a finalized order

-- | Lookup the order in a response to 'postFinalizeOrder'.
readOrderFinalized :: OrderFinalized -> Maybe (Order "order-created")
readOrderFinalized (OrderFinalized rsp) = decode $ HTTP.responseBody rsp

{- | Finalize an order after completing its challenges (i.e., once the order
is @ready@): sends the CSR, whose names must be the identifiers of the
order.
-}
postFinalizeOrder :: JWS.JWK -> KID -> Url "finalize-order" -> Finalize -> Nonce -> IO (Either AcmeError OrderFinalized)
postFinalizeOrder jwk kid finalizeurl finalizeobj nonce = do
    ebody <- (kidSign jwk ep kid nonce $ encode $ serialized)
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap OrderFinalized e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    ep :: Endpoint "finalize-order"
    ep = coerce finalizeurl
    serialized =
        object $
            [ "csr" .= finalizeobj.csr
            ]
