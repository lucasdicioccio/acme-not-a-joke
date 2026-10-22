{-# LANGUAGE GeneralizedNewtypeDeriving #-}

--- | Helpers to work with JSON Web Signatures for ACME.
-- Indeed, almost all ACME API calls are signed with a KID or a JWK and
-- transferred using the JWS format. Thus, some internal helpers are welcome.
module Acme.NotAJoke.Api.JWS where

import Control.Applicative ((<|>))
import Control.Exception (Exception, throwIO)
import Control.Lens hiding ((.=))
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError)
import Data.Aeson (FromJSON (..), ToJSON (..), Value (..), (.=))
import Data.ByteString.Lazy (ByteString)
import Data.Coerce (coerce)
import Data.Text (Text)

import qualified Crypto.JOSE.JWA.JWK as JWA
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Nonce

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
acmeJwsHeader f s@(AcmeHeader{_jwsHeader = a}) =
    fmap (\a' -> s{_jwsHeader = a'}) (f a)

acmeNonce :: Lens' (AcmeHeader p) Nonce
acmeNonce f s@(AcmeHeader{_acmeNonce = a}) =
    fmap (\a' -> s{_acmeNonce = a'}) (f a)

acmeURL :: Lens' (AcmeHeader p) RawEndpoint
acmeURL f s@(AcmeHeader{_acmeURL = a}) =
    fmap (\a' -> s{_acmeURL = a'}) (f a)

acmeAuthBit :: Lens' (AcmeHeader p) (Either PublicJWK KID)
acmeAuthBit f s@(AcmeHeader{_acmeAuthBit = a}) =
    fmap (\a' -> s{_acmeAuthBit = a'}) (f a)

instance JWS.HasJWSHeader AcmeHeader where
    jwsHeader = acmeJwsHeader

instance JWS.HasParams AcmeHeader where
    parseParamsFor proxy hp hu =
        AcmeHeader
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

{- | The JWS algorithm used to sign ACME requests with a given key.

If the key pins an algorithm (its @alg@ parameter, see 'setAcmeJWSAlg'), that
algorithm is used. Otherwise the algorithm follows from the key material:

* RSA keys sign with @RS256@ (the one algorithm all ACME servers must accept,
  RFC-8555 section 6.2),
* EC keys sign with @ES256@ (P-256), @ES384@ (P-384), @ES512@ (P-521) or
  @ES256K@ (secp256k1),
* OKP keys (Ed25519 and Ed448) sign with @EdDSA@.

Symmetric keys, as well as the @none@ and MAC algorithms, are refused: ACME
servers must reject them. X25519 and X448 keys cannot sign at all. Which of
the other algorithms are accepted is up to the ACME server (Let's Encrypt
accepts @RS256@, @ES256@ and @ES384@).

Call this function (or 'acmeProtectedHeader') to build any JWS for ACME,
including those without an 'AcmeHeader' (e.g., the inner JWS of a key change).
-}
acmeJWSAlg :: (MonadError e m, JWS.AsError e) => JWK.JWK -> m JWS.Alg
acmeJWSAlg jwk =
    case view JWK.jwkAlg jwk of
        Just (JWK.JWSAlg alg)
            | alg `elem` [JWS.None, JWS.HS256, JWS.HS384, JWS.HS512] ->
                throwing JWS._AlgorithmMismatch ("ACME refuses the JWS algorithm " <> show alg)
            | otherwise -> pure alg
        Just (JWK.JWEAlg _) ->
            throwing JWS._AlgorithmMismatch "this JWK is an encryption key"
        Nothing ->
            case view JWK.jwkMaterial jwk of
                JWA.RSAKeyMaterial _ -> pure JWS.RS256
                JWA.ECKeyMaterial k -> pure $ case view JWA.ecCrv k of
                    JWA.P_256 -> JWS.ES256
                    JWA.P_384 -> JWS.ES384
                    JWA.P_521 -> JWS.ES512
                    JWA.Secp256k1 -> JWS.ES256K
                JWA.OKPKeyMaterial (JWA.Ed25519Key _ _) -> pure JWS.EdDSA
                JWA.OKPKeyMaterial (JWA.Ed448Key _ _) -> pure JWS.EdDSA
                JWA.OKPKeyMaterial _ ->
                    throwing JWS._KeyMismatch "X25519 and X448 keys cannot sign"
                JWA.OctKeyMaterial _ ->
                    throwing JWS._AlgorithmMismatch "ACME refuses MAC-based (symmetric) signatures"

{- | Pins the JWS algorithm with which a key signs ACME requests (see
'acmeJWSAlg'), e.g., @PS256@ for an RSA key if your ACME server accepts it.

The algorithm is stored in the @alg@ parameter of the JWK, hence it is kept
when the key is written with 'Acme.NotAJoke.KeyManagement.writeJWKFile'.
Signing fails if the algorithm does not fit the key.
-}
setAcmeJWSAlg :: JWS.Alg -> JWK.JWK -> JWK.JWK
setAcmeJWSAlg alg = Control.Lens.set JWK.jwkAlg (Just (JWK.JWSAlg alg))

{- | A protected JWS header signed with the algorithm of 'acmeJWSAlg', the
starting point of the header of any ACME request.
-}
acmeProtectedHeader :: (MonadError e m, JWS.AsError e) => JWK.JWK -> m (JWS.JWSHeader JWS.Protection)
acmeProtectedHeader jwk = do
    alg <- acmeJWSAlg jwk
    pure $ JWS.newJWSHeader (JWS.Protected, alg)

{- | Signs a request with a key and carries its public key (in a @jwk@
header).

Used to create or fetch an account, and to revoke a certificate with the key
of the certificate. The algorithm follows from the key, see 'acmeJWSAlg'.
-}
jwkSign :: JWS.JWK -> Endpoint a -> Nonce -> ByteString -> IO (Either JWS.Error (JWS.FlattenedJWS AcmeHeader))
jwkSign jwk ep nonce payload = do
    jwk2 <- maybe (throwIO NoPublicKeyInJWK) pure $ publicJWK jwk
    JWS.runJOSE $ do
        hdr <- acmeProtectedHeader jwk
        let header = AcmeHeader hdr (raw ep) nonce (Left jwk2)
        JWS.signJWS payload (pure (header, jwk))

{- | Signs a request with the key of an account and names the account (in a
@kid@ header).

The algorithm follows from the key, see 'acmeJWSAlg'.
-}
kidSign :: JWS.JWK -> Endpoint a -> KID -> Nonce -> ByteString -> IO (Either JWS.Error (JWS.FlattenedJWS AcmeHeader))
kidSign jwk ep kid nonce payload = JWS.runJOSE $ do
    hdr <- acmeProtectedHeader jwk
    let header = AcmeHeader hdr (raw ep) nonce (Right kid)
    JWS.signJWS payload (pure (header, jwk))

newtype EmptyObject = EmptyObject Value
    deriving (Show, FromJSON, ToJSON)

emptyObject :: EmptyObject
emptyObject = EmptyObject (Object mempty)

newtype EmptyText = EmptyText Value
    deriving (Show, FromJSON, ToJSON)

emptyText :: EmptyText
emptyText = EmptyText (String mempty)
