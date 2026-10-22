{- | The ACME flow, composed out of the API calls of the @Acme.NotAJoke.Api.*@
modules.

'prepareAcmeOrder' runs the requests from the directory to the challenges of
an order (fetch the directory, find the account, create the order, inspect its
authorizations and pick a challenge for each) and returns an 'AcmeSingle':
the remaining calls, with the URLs, KID and nonces filled in. Most programs
do not call it directly but go through "Acme.NotAJoke.Dancer", which also
runs the remaining calls.

The other functions of this module wrap single operations (changing the
account key, revoking a certificate) the same way: given the base URL of the
server and the account key, they fetch the directory, a nonce and the account
before sending the request.
-}
module Acme.NotAJoke.Client where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Data.Coerce (Coercible, coerce)
import qualified Data.List as List
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as Text

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.Authorization
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Certificate
import Acme.NotAJoke.Api.Challenge
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.KeyChange
import Acme.NotAJoke.Api.Nonce as Nonce
import Acme.NotAJoke.Api.Order
import Acme.NotAJoke.Api.Revocation
import Acme.NotAJoke.Api.Validation

{- | An IO-type for ACME primitives.
Errors from the ACME server are returned as values (see 'AcmeError').
As we iterate on this lib, this type may change to become a monad-stack/mtl-mashup.
-}
type AcmePrim a = IO (Either AcmeError a)

{- | An object carrying all functions to drive a single order to a certificate,
once the order is created and its authorizations are inspected.
-}
data AcmeSingle = AcmeSingle
    { dir :: Directory
    -- ^ directory for the Server
    , nonces :: Nonce.Fetcher
    -- ^ an object to generate new nonces for this ACME server, saving found nonces opportunistically
    , pollOrder :: AcmePrim OrderInspected
    -- ^ fetches the status of an order
    , pendingAuthorizations :: [AcmeAuthorization]
    -- ^ the authorizations the client still has to validate, one per
    -- identifier of the order (authorizations the server already considers
    -- valid, e.g. reused from an earlier order, are left out)
    , finalizeOrder :: AcmePrim OrderFinalized
    -- ^ finalize the order (i.e, effectively sends the CSR to the server)
    , fetchCertificate :: Url "certificate" -> AcmePrim Certificate
    -- ^ fetch the signed certificate, the URL comes from a OrderInspected (see readOrderInspected)
    }

{- | An authorization of an order, with the challenge picked to validate it.

For a wildcard identifier such as @*.example.com@, the server gives an
authorization for @example.com@ with 'authWildcard' set (RFC-8555 section 7.1.3),
which only a DNS-01 challenge can validate. An order for both
@*.example.com@ and @example.com@ has two such authorizations for the same
@example.com@ value, hence two TXT records at the same name (see
'dns01RecordName'), which must be present at the same time.
-}
data AcmeAuthorization = AcmeAuthorization
    { authorizationUrl :: Url "authorization"
    -- ^ where the authorization lives
    , authIdentifier :: AuthorizationIdentifier
    -- ^ the identifier to prove control of (without the @*.@ of a wildcard)
    , authWildcard :: Bool
    -- ^ whether the authorization is for the wildcard of 'authIdentifier'
    , proof :: (Token, KeyAuthorization, ValidationProof)
    -- ^ the validation proof (i.e., the value to set in DNS records and so on)
    , fetchAuthorization :: AcmePrim AuthorizationInspected
    -- ^ fetches the authorization (e.g. to know why it failed)
    , replyChallenge :: AcmePrim ChallengeAttempted
    -- ^ tells the server it can validate the challenge (i.e., after writing the proof in some DNS record)
    , pollChallenge :: AcmePrim ChallengeAttempted
    -- ^ fetches the status of a challenge (mainly to know if the server has validated the challenge)
    }

{- | The name of the TXT record holding the 'ValidationProof' of a DNS-01
challenge: @_acme-challenge.example.com@ for @example.com@ as well as for the
wildcard @*.example.com@ (RFC-8555 section 8.4).
-}
dns01RecordName :: AuthorizationIdentifier -> Text
dns01RecordName ident = "_acme-challenge." <> wildcardBase ident.value

{- | The domain a wildcard domain covers: @example.com@ for @*.example.com@,
other domains are returned as they are.
-}
wildcardBase :: Text -> Text
wildcardBase domain = fromMaybe domain (Text.stripPrefix "*." domain)

-- | Whether a domain is a wildcard such as @*.example.com@.
isWildcardDomain :: Text -> Bool
isWildcardDomain = Text.isPrefixOf "*."

{- | Changes the key of an account (RFC-8555 section 7.3.5), see
'Acme.NotAJoke.Api.KeyChange'.

Fetches the directory and the account with the old key (the account must
exist, see 'fetchAccount'), then asks the server to replace the old key with
the new one. Once this succeeds, only the new key can sign requests for the
account: save it before calling this function.
-}
changeAccountKey ::
    BaseUrl ->
    -- | old (current) key of the account
    JWK.JWK ->
    -- | new key of the account
    JWK.JWK ->
    Account "account-fetch" ->
    IO (Either AcmeError KeyChanged)
changeAccountKey baseurl oldJwk newJwk account = runExceptT $ do
    acmeDir <- ExceptT $ fetchDirectory (directory baseurl)
    nf <- liftIO $ fetcher (getNonce acmeDir.newNonce)
    let nonceify :: (Nonce -> AcmePrim a) -> AcmePrim a
        nonceify f = either (pure . Left) f =<< nf.produce
    accountCreated <- ExceptT $ saveNonce nf (nonceify $ \nonce -> postFetchAccount oldJwk acmeDir.newAccount nonce account)
    kid <- maybe (throwE $ UnexpectedResponse "no account location" (coerce accountCreated)) pure $ readKID accountCreated
    ExceptT $ nonceify $ postKeyChange oldJwk newJwk kid acmeDir.keyChange

-- | Progress of 'prepareAcmeOrder', reported to its step handler.
data PrepareStep
    = Starting
    | -- | the directory of the server is fetched
      GotDirectory Directory
    | -- | a fresh nonce is about to be fetched
      GettingNonce
    | -- | the account is found (see 'readKID')
      GotAccount AccountCreated
    | -- | the order is created
      GotOrder OrderCreated
    | -- | emitted once per authorization of the order
      GotAuthorization AuthorizationInspected

{- | Picks the type of challenge to validate authorizations with (e.g.,
'isDNS01').
-}
type MatchChallenge = Challenge "challenge-unspecified" -> Bool

{- | Picks, among the authorizations of an order, the ones the client has to
validate, and the challenge to validate each of them with. The @tag@ is
carried along (e.g. the URL of the authorization).

Valid authorizations are left out (the server may reuse an authorization
validated for an earlier order). Fails on the first authorization to validate
that has no matching challenge (e.g. a wildcard authorization with an HTTP-01
matcher), or which is neither pending nor valid, with its tag and a message.
-}
pickChallenges ::
    MatchChallenge ->
    [(tag, Authorization "authorization-inspected")] ->
    Either (tag, Text) [(tag, Authorization "authorization-inspected", Challenge "challenge-unspecified")]
pickChallenges matchChallenge = fmap concat . traverse pick
  where
    pick (tag, authz) =
        case authz.status of
            AuthorizationValid -> Right []
            AuthorizationPending ->
                case List.find matchChallenge authz.challenges of
                    Just challenge -> Right [(tag, authz, challenge)]
                    Nothing -> Left (tag, "no matching challenge in authorization for " <> describe authz)
            st -> Left (tag, "authorization for " <> describe authz <> " is " <> Text.pack (show st))
    describe :: Authorization "authorization-inspected" -> Text
    describe authz =
        (if authz.wildcard == Just True then "*." else "") <> authz.identifier.value

{- | Runs the first steps of the ACME dance: up to the point where the client
has to prove it controls the identifiers in the order.

All the authorizations of the order are inspected, one challenge is picked
per authorization still to validate (see 'pickChallenges').

Stops at the first error, which is returned.
-}
prepareAcmeOrder ::
    BaseUrl ->
    JWK.JWK ->
    Account "account-fetch" ->
    CSR ->
    Order "order-create" ->
    MatchChallenge ->
    (PrepareStep -> IO ()) ->
    IO (Either AcmeError AcmeSingle)
prepareAcmeOrder baseurl jwk account csr1 order matchChallenge handleStep = runExceptT $ do
    step $ Starting

    -- unauthenticated info
    acmeDir <- ExceptT $ fetchDirectory (directory baseurl)
    nf <- liftIO $ fetcher (handleStep GettingNonce >> getNonce acmeDir.newNonce)
    let nonceify :: (Nonce -> AcmePrim a) -> AcmePrim a
        nonceify f = either (pure . Left) f =<< nf.produce
    step $ GotDirectory acmeDir

    -- fetch account
    accountCreated <- ExceptT $ saveNonce nf (nonceify $ \nonce -> postFetchAccount jwk acmeDir.newAccount nonce account)
    kid <- expect "no account location" accountCreated $ readKID accountCreated
    step $ GotAccount accountCreated

    -- prepare new order
    orderCreated <- ExceptT $ saveNonce nf (nonceify $ \nonce -> postNewOrder jwk acmeDir.newOrder kid nonce order)
    authUrls <- expect "no authorization in order" orderCreated $ nonEmpty . authorizations =<< readOrderCreated orderCreated
    step $ GotOrder orderCreated

    -- poller for order
    orderUrl <- expect "no order location" orderCreated $ readOrderUrl orderCreated
    let fpollOrder = saveNonce nf (nonceify $ postGetOrder jwk orderUrl kid)

    -- inspect every authorization of the order
    let ffetchAuthorization authUrl = saveNonce nf (nonceify $ postGetAuthorization jwk kid authUrl)
    inspected <- traverse (inspectAuthorization ffetchAuthorization) authUrls
    picked <- case pickChallenges matchChallenge [((authUrl, rsp), authz) | (authUrl, rsp, authz) <- inspected] of
        Right xs -> pure xs
        Left ((_, rsp), what) -> throwE $ UnexpectedResponse what (coerce rsp)

    let acmeAuthorization ((authUrl, _), authz, challenge) =
            let tok = challenge.token
                keyAuth = keyAuthorization tok jwk
             in AcmeAuthorization
                    { authorizationUrl = authUrl
                    , authIdentifier = authz.identifier
                    , authWildcard = authz.wildcard == Just True
                    , proof = (tok, keyAuth, sha256digest keyAuth)
                    , fetchAuthorization = ffetchAuthorization authUrl
                    , replyChallenge = saveNonce nf (nonceify $ postReplyChallenge jwk kid challenge)
                    , pollChallenge = saveNonce nf (nonceify $ postGetChallenge jwk kid challenge)
                    }

    -- finalize order
    finalizeOrderUrl <- expect "no finalize url in order" orderCreated $ fmap finalize $ readOrderCreated orderCreated
    let ffinalizeOrder = saveNonce nf (nonceify $ postFinalizeOrder jwk kid finalizeOrderUrl (Finalize csr1))

    -- fetch certificate (at last)
    let ffetchCertificate certificateUrl = saveNonce nf (nonceify $ postGetCertificate jwk kid certificateUrl)

    pure $ AcmeSingle acmeDir nf fpollOrder (map acmeAuthorization picked) ffinalizeOrder ffetchCertificate
  where
    step :: PrepareStep -> ExceptT AcmeError IO ()
    step = liftIO . handleStep

    inspectAuthorization fetchAuthz authUrl = do
        authorizationInspected <- ExceptT $ fetchAuthz authUrl
        step $ GotAuthorization authorizationInspected
        authz <- expect "could not read authorization" authorizationInspected $ readAuthorization authorizationInspected
        pure (authUrl, authorizationInspected, authz)

    -- turns a failed lookup in a (successful) response into an error
    expect :: (Coercible rsp Response) => Text -> rsp -> Maybe x -> ExceptT AcmeError IO x
    expect what rsp = maybe (throwE $ UnexpectedResponse what (coerce rsp)) pure

    nonEmpty :: [x] -> Maybe [x]
    nonEmpty [] = Nothing
    nonEmpty xs = Just xs

{- | Revokes a certificate with the account key (RFC-8555 section 7.6).

Fetches the directory and the account (which must exist, see 'fetchAccount'),
then sends the revocation signed with the KID of the account. The account must
be the one which ordered the certificate, or hold valid authorizations for all
its names.
-}
revokeCertificate ::
    BaseUrl ->
    JWK.JWK ->
    Account "account-fetch" ->
    Revocation ->
    IO (Either AcmeError CertificateRevoked)
revokeCertificate baseurl jwk account rev = runExceptT $ do
    acmeDir <- ExceptT $ fetchDirectory (directory baseurl)
    nf <- liftIO $ fetcher (getNonce acmeDir.newNonce)
    accountCreated <- ExceptT $ saveNonce nf (withNonce nf $ \nonce -> postFetchAccount jwk acmeDir.newAccount nonce account)
    kid <- maybe (throwE $ UnexpectedResponse "no account location" (coerce accountCreated)) pure $ readKID accountCreated
    ExceptT $ withNonce nf $ \nonce -> postRevokeCertificate jwk kid acmeDir.revokeCert nonce rev

{- | Revokes a certificate with its own key (RFC-8555 section 7.6), given as
a JWK (see 'Acme.NotAJoke.KeyManagement.jwkFromRSAKey').

No account is involved, which makes it the way to revoke a certificate whose
account key is lost, or whose key is compromised.
-}
revokeCertificateWithCertKey ::
    BaseUrl ->
    JWK.JWK ->
    Revocation ->
    IO (Either AcmeError CertificateRevoked)
revokeCertificateWithCertKey baseurl certJwk rev = runExceptT $ do
    acmeDir <- ExceptT $ fetchDirectory (directory baseurl)
    nonce <- ExceptT $ getNonce acmeDir.newNonce
    ExceptT $ postRevokeCertificateWithCertKey certJwk acmeDir.revokeCert nonce rev

-- | Runs an API call with a nonce from a fetcher.
withNonce :: Nonce.Fetcher -> (Nonce -> AcmePrim a) -> AcmePrim a
withNonce nf f = either (pure . Left) f =<< nf.produce
