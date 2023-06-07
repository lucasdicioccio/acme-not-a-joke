{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE DuplicateRecordFields #-}

-- https://www.rfc-editor.org/rfc/rfc8555.txt
-- TODO: tweak supported algos
-- TODO: more to save/load jwk/pem
-- TODO: keyChange
-- TODO: deactivate account
module Acme.NotAJoke.Client where

import Control.Applicative ((<|>))
import Control.Exception (Exception, throwIO)
import GHC.TypeLits
import GHC.Generics (Generic)
import Data.Coerce (coerce, Coercible)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text as Text
import Data.Aeson (FromJSON(..), withText, withObject,ToJSON(..), pairs, encode, (.=), (.:), (.:?), object, decode, Value(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))
import Data.Time.Clock (UTCTime)
import Data.Maybe (catMaybes)
import qualified Data.List as List

import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.JWK as JWK

newtype Endpoint (s :: Symbol) = Endpoint Text
  deriving (Show, FromJSON)
type RawEndpoint = Text

newtype Url (s :: Symbol) = Url Text
  deriving (Show, FromJSON, ToJSON)

type CAAIdentity = Text
type BaseUrl = Text

letsencryptv2 :: BaseUrl
letsencryptv2 = "https://acme-v02.api.letsencrypt.org/"

staging_letsencryptv2 :: BaseUrl
staging_letsencryptv2 = "https://acme-staging-v02.api.letsencrypt.org/"

get :: Endpoint a -> IO (Wreq.Response ByteString)
get ep = Wreq.get (wrequrl ep)

raw :: Endpoint a -> RawEndpoint
raw = coerce

wrequrl :: Endpoint a -> String
wrequrl = Text.unpack . coerce

--- DIRECTORY

data Meta
  = Meta
  { caaIdentities :: [ CAAIdentity ]
  , termsOfService :: Url "TOS"
  , website :: Url "website"
  } deriving (Show, Generic)
instance FromJSON Meta

data Directory
  = Directory
  { meta :: Meta
  , newNonce :: Endpoint "newNonce"
  , newAccount :: Endpoint "newAccount"
  , newOrder :: Endpoint "newOrder" 
  , keyChange :: Endpoint "keyChange"
  , renewalInfo :: Endpoint "renewalInfo"
  , revokeCert :: Endpoint "revokeCert"
  } deriving (Show, Generic)
instance FromJSON Directory

directory :: BaseUrl -> Endpoint "directory"
directory baseUrl = coerce $ baseUrl <> "directory"

fetchDirectory :: Endpoint "directory" -> IO Directory
fetchDirectory ep = do
  r <- Wreq.asJSON =<< get ep
  pure $ r ^. Wreq.responseBody

-- NONCE

newtype Nonce = Nonce Text
  deriving (Show, FromJSON, ToJSON)

getNonce :: Endpoint "newNonce" -> IO (Maybe Nonce)
getNonce ep = do
  r <- Wreq.head_ (wrequrl ep)
  pure $ responseNonceWreq r
  where

type family Field (a :: Symbol) (k :: Symbol) v

responseNonceWreq :: forall a. Wreq.Response a -> Maybe Nonce
responseNonceWreq r =
  r ^? Wreq.responseHeader "replay-nonce" . to Encoding.decodeUtf8 . to Nonce

responseNonceWreqBS :: Wreq.Response ByteString -> Maybe Nonce
responseNonceWreqBS = responseNonceWreq

responseNonce :: forall a. Coercible a (Wreq.Response ByteString) => a -> Maybe Nonce
responseNonce = responseNonceWreqBS . coerce

-- ACCOUNT

type Contact = Text

data AccountStatus
  = AccountValid
  | AccountDeactivated
  | AccountRevoked
  deriving (Show, Eq)

data Account a
  = Account
  { status :: Field a "status" AccountStatus
  , orders :: Field a "orders" (Endpoint "orders")
  , agreement :: Field a "agreement" (Url "TOS")
  , termsOfServiceAgreed :: Field a "termsOfServiceAgreed" Bool
  , contact :: Field a "contact" [ Contact ]
  , onlyReturnExisting :: Field a "onlyReturnExisting" Bool
  }

type instance Field "account-create" "termsOfServiceAgreed" x = x
type instance Field "account-create" "contact" x = x
type instance Field "account-create" "status" x = ()
type instance Field "account-create" "orders" x = ()
type instance Field "account-create" "agreement" x = ()
type instance Field "account-create" "onlyReturnExisting" x = ()

type instance Field "account-fetch" "termsOfServiceAgreed" x = x
type instance Field "account-fetch" "contact" x = x
type instance Field "account-fetch" "status" x = ()
type instance Field "account-fetch" "orders" x = ()
type instance Field "account-fetch" "agreement" x = ()
type instance Field "account-fetch" "onlyReturnExisting" x = x

newtype AccountCreated = AccountCreated (Wreq.Response ByteString)
  deriving Show

readKID :: AccountCreated -> Maybe KID
readKID (AccountCreated rsp) = rsp ^? Wreq.responseHeader "location" . to (KID . Encoding.decodeUtf8)

createAccount :: [ Contact ] -> Account "account-create"
createAccount = createAccount1 True

createAccount1 :: Bool -> [ Contact ] -> Account "account-create"
createAccount1 tos contacts = Account () () () tos contacts ()

fetchAccount :: [ Contact ] -> Account "account-fetch"
fetchAccount = fetchAccount1 True True

fetchAccount1 :: Bool -> Bool -> [ Contact ] -> Account "account-fetch"
fetchAccount1 tos onlyfetch contacts = Account () () () tos contacts onlyfetch

postCreateAccount :: JWS.JWK -> Endpoint "newAccount" -> Nonce -> Account "account-create" -> IO (Maybe AccountCreated)
postCreateAccount jwk ep nonce acc = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (jwkSign jwk ep nonce $ encode $ serialized)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ AccountCreated e
    Left err -> do
      print err
      pure Nothing

  where
    serialized = object [ "termsOfServiceAgreed" .= acc.termsOfServiceAgreed
                        , "contact" .= acc.contact
                        ]

postFetchAccount :: JWS.JWK -> Endpoint "newAccount" -> Nonce -> Account "account-fetch" -> IO (Maybe AccountCreated)
postFetchAccount jwk ep nonce acc = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (jwkSign jwk ep nonce $ encode $ serialized)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ AccountCreated e
    Left err -> do
      print err
      pure Nothing

  where
    serialized = object [ "termsOfServiceAgreed" .= acc.termsOfServiceAgreed
                        , "contact" .= acc.contact
                        , "onlyReturnExisting" .= acc.onlyReturnExisting
                        ]

-- ORDERS

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

data OrderType
  = DNSOrder
  deriving (Show, Eq, Ord)

instance ToJSON OrderType where
  toEncoding DNSOrder = toEncoding ("dns" :: Text)
  toJSON DNSOrder = toJSON ("dns" :: Text)
instance FromJSON OrderType where
  parseJSON = withText "Ordertype" $ \txt ->
                case txt of
                  "dns" -> pure DNSOrder
                  _     -> fail $ "invalid ordertype:" <> show txt

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

readOrderUrl :: OrderCreated -> Maybe (Url "order")
readOrderUrl (OrderCreated rsp) = rsp ^? Wreq.responseHeader "location" . to (Url . Encoding.decodeUtf8)

readOrderCreated :: OrderCreated -> Maybe (Order "order-created")
readOrderCreated (OrderCreated rsp) = decode $ rsp ^. Wreq.responseBody

createOrder :: (Maybe UTCTime, Maybe UTCTime) -> [ OrderIdentifier ] -> Order "order-create"
createOrder (nbefore,nafter) ois =
  Order ()() ois nbefore nafter () () () ()

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

-- Authorization
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

data ChallengeType
  = ChallengeDNS01
  | ChallengeHTTP01
  | ChallengeTLSALPN01
  | ChallengeUnspec Text
  deriving (Show, Eq, Ord)

instance FromJSON ChallengeType where
  parseJSON = withText "ChallengeType" $ \txt ->
                case txt of
                  "dns-01" -> pure ChallengeDNS01
                  "http-01" -> pure ChallengeHTTP01
                  "tls-alpn-01" -> pure ChallengeTLSALPN01
                  _     -> pure $ ChallengeUnspec txt

data ChallengeStatus
  = ChallengePending
  | ChallengeProcessing
  | ChallengeValid
  | ChallengeInvalid
  deriving (Show, Eq, Ord)

instance FromJSON ChallengeStatus where
  parseJSON = withText "ChallengeStatus" $ \txt ->
                case txt of
                  "pending" -> pure ChallengePending
                  "processing" -> pure ChallengeProcessing
                  "valid" -> pure ChallengeValid
                  "invalid" -> pure ChallengeInvalid
                  _     -> fail $ "invalid challenge status:" <> show txt

data Challenge a
  = Challenge
  { type_ :: ChallengeType
  , url :: Url "challenge"
  , status :: ChallengeStatus
  , validated :: Maybe UTCTime
  , error :: Maybe Problem
  --
  , token :: Field a "token" Token
  --
  , _sourceObject :: Value -- for extensibility
  }

type instance Field "challenge-unspecified" "token" x = x

isDNS01 :: Challenge "challenge-unspecified" -> Bool
isDNS01 challenge = challenge.type_ == ChallengeDNS01

instance FromJSON (Challenge "challenge-unspecified") where
  parseJSON = withObject "Challenge(unspecified)" $ \v ->
                Challenge
                  <$> v .: "type"
                  <*> v .: "url"
                  <*> v .: "status"
                  <*> v .:? "validated"
                  <*> v .:? "error"
                  <*> v .: "token"
                  <*> (pure $ Object v)

data Authorization a
  = Authorization
  { status :: Field a "status" AuthorizationStatus
  , identifier :: Field a "status" AuthorizationIdentifier
  , expires :: Field a "expires" (Maybe UTCTime)
  , challenges :: Field a "challenges" [Challenge "challenge-unspecified"]
  , wildcard :: Field a "wildcard" (Maybe Bool)
  }

newtype EmptyObject = EmptyObject Value
  deriving (Show, FromJSON, ToJSON)

emptyObject :: EmptyObject
emptyObject = EmptyObject (Object mempty)

newtype EmptyText = EmptyText Value
  deriving (Show, FromJSON, ToJSON)

emptyText :: EmptyText
emptyText = EmptyText (String mempty)

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

readAuthorization :: AuthorizationInspected -> Maybe (Authorization "authorization-inspected")
readAuthorization (AuthorizationInspected rsp) = decode $ rsp ^. Wreq.responseBody

postGetAuthorization :: JWS.JWK -> KID -> Nonce -> Url "authorization" -> IO (Maybe AuthorizationInspected)
postGetAuthorization jwk kid nonce authUrl = do
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

newtype ChallengeAttempted = ChallengeAttempted (Wreq.Response ByteString)
  deriving (Show)

postReplyChallenge :: JWS.JWK -> KID -> Nonce -> Challenge a -> IO (Maybe ChallengeAttempted)
postReplyChallenge jwk kid nonce challenge = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce $ encode emptyObject)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ ChallengeAttempted e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)

postGetChallenge :: JWS.JWK -> KID -> Nonce -> Challenge a -> IO (Maybe ChallengeAttempted)
postGetChallenge jwk kid nonce challenge = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce "")
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ ChallengeAttempted e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)

-- CSR

newtype Base64DER = Base64DER Text
  deriving (Show, FromJSON, ToJSON)

newtype CSR = CSR Base64DER
  deriving (Show, FromJSON, ToJSON)

data Finalize
  = Finalize
  { csr :: CSR
  }

newtype OrderFinalized = OrderFinalized (Wreq.Response ByteString)
  deriving (Show)

readOrderFinalized :: OrderFinalized -> Maybe (Order "order-created")
readOrderFinalized (OrderFinalized rsp) = decode $ rsp ^. Wreq.responseBody

postFinalizeOrder :: JWS.JWK -> KID -> Nonce -> Url "finalize-order" -> Finalize -> IO (Maybe OrderFinalized)
postFinalizeOrder jwk kid nonce finalizeurl finalizeobj = do
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

-- Certificate

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

-- Token and KeyAuthorization

newtype Token = Token Text
  deriving (Eq, Ord, FromJSON)

newtype KeyAuthorization = KeyAuthorization Text
  deriving (Eq, Ord)

keyAuthorization :: Token -> JWK.JWK -> KeyAuthorization
keyAuthorization tok jwk =
    KeyAuthorization txt
  where
    txt,tok',b64thumbprint :: Text
    txt = tok' <> "." <> b64thumbprint
    tok' = coerce tok
    b64thumbprint = Encoding.decodeUtf8 $ review (JWK.base64url . JWK.digest) tprint

    tprint :: JWK.Digest JWK.SHA256
    tprint = view JWK.thumbprint jwk

newtype ValidationProof = ValidationProof Text
  deriving (Eq)

sha256digest :: KeyAuthorization -> ValidationProof
sha256digest (KeyAuthorization kauth) =
  ValidationProof
    $ Encoding.decodeUtf8 
    $ review (JWK.base64url . JWK.digest)
    hash
  where
    hash :: JWK.Digest JWK.SHA256
    hash = JWK.hash $ Encoding.encodeUtf8 kauth

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

doLoadJWK :: FilePath -> IO (Maybe JWK.JWK)
doLoadJWK = fmap decode . LBS.readFile

doLoadDER :: FilePath -> IO Base64DER
doLoadDER = fmap (Base64DER . Encoding.decodeUtf8 . review JWK.base64url) . LBS.readFile

doGenJWK :: IO JWK.JWK
doGenJWK = JWK.genJWK (JWK.RSAGenParam (4096 `div` 8))

-- Problem

type Problem = Value

-- Bundle Acme

type AcmePrim a = Nonce -> IO (Maybe a)
data Acme = Acme
  { dir                :: Directory
  , newNonce           :: IO (Maybe Nonce)
  --
  , pollOrder          :: AcmePrim OrderInspected
  , fetchAuthorization :: AcmePrim AuthorizationInspected
  , proof              :: ValidationProof
  -- ^ so far limited to 1st authorization URL from OrderInspected
  , replyChallenge     :: AcmePrim ChallengeAttempted
  -- ^ so far limited to DNS-01 challenge from AuthorizationInspected
  , pollChallenge      :: AcmePrim ChallengeAttempted
  , finalizeOrder      :: AcmePrim OrderFinalized
  , fetchCertificate   :: Url "certificate" -> AcmePrim Certificate
  -- ^ URL comes from a OrderInspected (see readOrderInspected)
  }

orderAcme :: BaseUrl -> JWK.JWK -> Account "account-fetch" -> CSR -> Order "order-create" -> IO Acme
orderAcme baseurl jwk account csr order = do
  -- unauthenticated info
  dir <- fetchDirectory (directory baseurl)
  let newNonce = getNonce dir.newNonce

  -- fetch account
  Just nonce1 <- newNonce
  Just accountCreated <- postFetchAccount jwk (newAccount dir) nonce1 account
  let (Just nonce2) = responseNonce accountCreated
  let (Just kid) = readKID accountCreated

  -- prepare new order
  Just orderCreated <- postNewOrder jwk (newOrder dir) kid nonce2 order
  let (Just nonce3) = responseNonce orderCreated
  let Just authUrl = fmap (head . authorizations) $ readOrderCreated orderCreated

  -- poller for order
  let Just orderUrl = readOrderUrl orderCreated
  let pollOrder nonce = postGetOrder jwk orderUrl kid nonce

  -- read authorization's dns challenge 
  let fetchAuthorization nonce = postGetAuthorization jwk kid nonce authUrl
  Just authorizationInspected <- fetchAuthorization nonce3
  let (Just nonce4) = responseNonce authorizationInspected
  let Just challenge = List.find isDNS01 . challenges =<< readAuthorization authorizationInspected

  -- read authorization's dns challenge 
  let replyChallenge nonce = postReplyChallenge jwk kid nonce challenge
  let pollChallenge nonce = postGetChallenge jwk kid nonce challenge

  -- challenge validation proof
  let proof = sha256digest (keyAuthorization (token challenge) jwk)

  -- finalize order
  let Just finalizeOrderUrl = fmap finalize $ readOrderCreated orderCreated
  let finalizeOrder nonce = postFinalizeOrder jwk kid nonce finalizeOrderUrl (Finalize csr)

  -- fetch certificate (at last)
  let fetchCertificate certificateUrl nonce = postGetCertificate jwk kid nonce certificateUrl

  pure $ Acme dir newNonce pollOrder fetchAuthorization proof replyChallenge pollChallenge finalizeOrder fetchCertificate
