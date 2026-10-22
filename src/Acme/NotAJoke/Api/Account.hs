{- | ACME accounts (RFC-8555 section 7.3).

Every request but the ones fetching the directory and a nonce is signed by an
account key (a JWK, see "Acme.NotAJoke.KeyManagement"). The server knows the
account by its public key: the first request, to the @newAccount@ endpoint of
the 'Acme.NotAJoke.Api.Directory.Directory', creates the account (or finds the
existing one) and returns its URL in the @Location@ header (see 'readKID').
Later requests are signed with that URL as a @kid@ (see
'Acme.NotAJoke.Api.JWS.kidSign').

'Account' has two states (see "Acme.NotAJoke.Api.Field"):

* @Account \"account-create\"@ ('createAccount', 'postCreateAccount') creates
  the account if needed
* @Account \"account-fetch\"@ ('fetchAccount', 'postFetchAccount') only finds an
  existing account: the server rejects the request when the key has no
  account; this is the state 'Acme.NotAJoke.Dancer.AcmeDancer' and the
  functions of "Acme.NotAJoke.Client" take

Hence a program first creates its account once (e.g., when it creates the
account key), then fetches it.
-}
module Acme.NotAJoke.Api.Account where

import Data.Aeson (encode, object, (.=))
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Field
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Nonce

-- | The contact-field of an account (something like `mailto:certmaster@example.com`)
type Contact = Text

-- | An RFC-defined account status.
data AccountStatus
    = AccountValid
    | AccountDeactivated
    | AccountRevoked
    deriving (Show, Eq)

{- | A structure holding various Account field, the set of fields depending on
the state @a@ (@\"account-create\"@ or @\"account-fetch\"@).
-}
data Account a
    = Account
    { status :: Field a "status" AccountStatus
    , orders :: Field a "orders" (Endpoint "orders")
    , agreement :: Field a "agreement" (Url "TOS")
    , termsOfServiceAgreed :: Field a "termsOfServiceAgreed" Bool
    , contact :: Field a "contact" [Contact]
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

{- | The response of the server to 'postCreateAccount' or 'postFetchAccount',
whose @Location@ header gives the KID of the account (see 'readKID').
-}
newtype AccountCreated = AccountCreated Response
    deriving (Show)

-- | Initializes an account structure, assuming we have read the terms-of-service.
createAccount :: [Contact] -> Account "account-create"
createAccount = createAccount1 True

-- | Whether you agree to the terms of service of the ACME server (see 'Acme.NotAJoke.Api.Meta.termsOfService').
type HasReadTermsOfService = Bool

-- | Initializes an account structure.
createAccount1 :: HasReadTermsOfService -> [Contact] -> Account "account-create"
createAccount1 tos contacts = Account () () () tos contacts ()

{- | Initializes a structure to look up an existing account (agreeing to the
terms-of-service and setting @onlyReturnExisting@). The server ignores the
contacts of a lookup (an existing account keeps its contacts).
-}
fetchAccount :: [Contact] -> Account "account-fetch"
fetchAccount = fetchAccount1 True True

{- | Initializes a structure to look up an account, with whether you agree to
the terms-of-service and whether the server must only return an existing
account (with @False@, the server creates the account when missing).
-}
fetchAccount1 :: Bool -> Bool -> [Contact] -> Account "account-fetch"
fetchAccount1 tos onlyfetch contacts = Account () () () tos contacts onlyfetch

-- | Lookup a Key Identifier for the account.
readKID :: AccountCreated -> Maybe KID
readKID (AccountCreated rsp) = KID . Encoding.decodeUtf8 <$> responseHeader "location" rsp

-- | Fetches or create an account (a single API call).
postCreateAccount :: JWS.JWK -> Endpoint "newAccount" -> Nonce -> Account "account-create" -> IO (Either AcmeError AccountCreated)
postCreateAccount jwk ep nonce acc = do
    ebody <- (jwkSign jwk ep nonce $ encode $ serialized)
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap AccountCreated e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    serialized =
        object
            [ "termsOfServiceAgreed" .= acc.termsOfServiceAgreed
            , "contact" .= acc.contact
            ]

-- | Only fetches an account (i.e., does not create the account if missing).
postFetchAccount :: JWS.JWK -> Endpoint "newAccount" -> Nonce -> Account "account-fetch" -> IO (Either AcmeError AccountCreated)
postFetchAccount jwk ep nonce acc = do
    ebody <- (jwkSign jwk ep nonce $ encode $ serialized)
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap AccountCreated e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    serialized =
        object
            [ "termsOfServiceAgreed" .= acc.termsOfServiceAgreed
            , "contact" .= acc.contact
            , "onlyReturnExisting" .= acc.onlyReturnExisting
            ]
