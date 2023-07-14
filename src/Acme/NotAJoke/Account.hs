module Acme.NotAJoke.Account where

import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (encode, (.=), object)
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Field
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.JWS

-- | The contact-field of an account (something like `mailto:certmaster@example.com`)
type Contact = Text

-- | An RFC-defined account status.
data AccountStatus
  = AccountValid
  | AccountDeactivated
  | AccountRevoked
  deriving (Show, Eq)

-- | A structure holding various Account field.
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

-- | Initializes an account structure, assuming we have read the terms-of-service.
createAccount :: [ Contact ] -> Account "account-create"
createAccount = createAccount1 True

type HasReadTermsOfService = Bool

-- | Initializes an account structure.
createAccount1 :: HasReadTermsOfService -> [ Contact ] -> Account "account-create"
createAccount1 tos contacts = Account () () () tos contacts ()

fetchAccount :: [ Contact ] -> Account "account-fetch"
fetchAccount = fetchAccount1 True True

fetchAccount1 :: Bool -> Bool -> [ Contact ] -> Account "account-fetch"
fetchAccount1 tos onlyfetch contacts = Account () () () tos contacts onlyfetch

-- | Lookup a Key Identifier for the account.
readKID :: AccountCreated -> Maybe KID
readKID (AccountCreated rsp) = rsp ^? Wreq.responseHeader "location" . to (KID . Encoding.decodeUtf8)

-- | Fetches or create an account (a single API call).
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

-- | Only fetches an account (i.e., does not create the account if missing).
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
