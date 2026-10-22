{- | Account key rollover (RFC-8555 section 7.3.5).

Changing the key of an account takes a nested JWS posted to the @keyChange@
endpoint of the 'Acme.NotAJoke.Api.Directory.Directory':

* the inner JWS is signed with the new key, carries the new (public) key in a
  @jwk@ header and has no nonce; its payload names the account and its old
  (public) key,
* the outer JWS is a regular ACME request signed with the old key (with the
  @kid@ of the account and a nonce), whose payload is the inner JWS.

Once the server has accepted the request, the account is only reachable with
the new key (the KID of the account does not change).
-}
module Acme.NotAJoke.Api.KeyChange where

import Control.Exception (throwIO)
import Control.Lens hiding ((.=))
import Data.Aeson (ToJSON (..), encode, object, (.=))

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Nonce

{- | Protected header of the inner JWS of a key change: like an 'AcmeHeader'
with a @jwk@ (the new key) but without a nonce.
-}
data KeyChangeHeader p
    = KeyChangeHeader
    { _keyChangeJwsHeader :: JWS.JWSHeader p
    , _keyChangeURL :: RawEndpoint
    , _keyChangeNewKey :: PublicJWK
    }

keyChangeJwsHeader :: Lens' (KeyChangeHeader p) (JWS.JWSHeader p)
keyChangeJwsHeader f s@(KeyChangeHeader{_keyChangeJwsHeader = a}) =
    fmap (\a' -> s{_keyChangeJwsHeader = a'}) (f a)

keyChangeURL :: Lens' (KeyChangeHeader p) RawEndpoint
keyChangeURL f s@(KeyChangeHeader{_keyChangeURL = a}) =
    fmap (\a' -> s{_keyChangeURL = a'}) (f a)

keyChangeNewKey :: Lens' (KeyChangeHeader p) PublicJWK
keyChangeNewKey f s@(KeyChangeHeader{_keyChangeNewKey = a}) =
    fmap (\a' -> s{_keyChangeNewKey = a'}) (f a)

instance JWS.HasJWSHeader KeyChangeHeader where
    jwsHeader = keyChangeJwsHeader

instance JWS.HasParams KeyChangeHeader where
    parseParamsFor proxy hp hu =
        KeyChangeHeader
            <$> JWS.parseParamsFor proxy hp hu
            <*> JWS.headerRequiredProtected "url" hp hu
            <*> JWS.headerRequiredProtected "jwk" hp hu
    params h =
        [ (True, "url" .= view keyChangeURL h)
        , (True, "jwk" .= view keyChangeNewKey h)
        ]
            <> JWS.params (view keyChangeJwsHeader h)
    extensions = const ["url", "jwk"]

-- | Payload of the inner JWS of a key change.
data KeyChange
    = KeyChange
    { account :: KID
    -- ^ the account whose key changes (its KID, i.e., its URL)
    , oldKey :: PublicJWK
    -- ^ the current key of the account
    }
    deriving (Show)

instance ToJSON KeyChange where
    toJSON kc =
        object
            [ "account" .= kc.account
            , "oldKey" .= kc.oldKey
            ]

newtype KeyChanged = KeyChanged Response
    deriving (Show)

{- | Signs the inner JWS of a key change with the new key.

Throws 'NoPublicKeyInJWK' if a public key cannot be derived from the old or
the new key (as 'jwkSign' does).
-}
keyChangeInnerSign ::
    -- | old key of the account
    JWS.JWK ->
    -- | new key of the account
    JWS.JWK ->
    KID ->
    Endpoint "keyChange" ->
    IO (Either JWS.Error (JWS.FlattenedJWS KeyChangeHeader))
keyChangeInnerSign oldJwk newJwk kid ep = do
    oldPub <- maybe (throwIO NoPublicKeyInJWK) pure $ publicJWK oldJwk
    newPub <- maybe (throwIO NoPublicKeyInJWK) pure $ publicJWK newJwk
    let payload = encode $ KeyChange kid oldPub
    JWS.runJOSE $ do
        -- alg <- JWS.bestJWSAlg newJwk
        let alg = JWS.RS256
        let header = KeyChangeHeader (JWS.newJWSHeader (JWS.Protected, alg)) (raw ep) newPub
        JWS.signJWS payload (pure (header, newJwk))

{- | Builds the whole (nested) key-change request: the inner JWS signed with
the new key, wrapped in an outer JWS signed with the old key.
-}
keyChangeSign ::
    -- | old key of the account
    JWS.JWK ->
    -- | new key of the account
    JWS.JWK ->
    KID ->
    Endpoint "keyChange" ->
    Nonce ->
    IO (Either JWS.Error (JWS.FlattenedJWS AcmeHeader))
keyChangeSign oldJwk newJwk kid ep nonce = do
    einner <- keyChangeInnerSign oldJwk newJwk kid ep
    case einner of
        Left err -> pure $ Left err
        Right inner -> kidSign oldJwk ep kid nonce (encode inner)

{- | Changes the key of an account (a single API call).

The server replies with a 409 Conflict (a 'ServerRejected', whose @location@
header is the account using it) when the new key is already used by another
account.
-}
postKeyChange ::
    -- | old key of the account
    JWS.JWK ->
    -- | new key of the account
    JWS.JWK ->
    KID ->
    Endpoint "keyChange" ->
    Nonce ->
    IO (Either AcmeError KeyChanged)
postKeyChange oldJwk newJwk kid ep nonce = do
    ebody <- keyChangeSign oldJwk newJwk kid ep nonce
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap KeyChanged e
        Left err -> do
            pure $ Left $ SigningFailed err
