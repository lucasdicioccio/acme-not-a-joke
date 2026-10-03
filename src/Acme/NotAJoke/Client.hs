module Acme.NotAJoke.Client where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Data.Coerce (Coercible, coerce)
import qualified Data.List as List
import Data.Text (Text)

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.Authorization
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Certificate
import Acme.NotAJoke.Api.Challenge
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Nonce as Nonce
import Acme.NotAJoke.Api.Order
import Acme.NotAJoke.Api.Validation

{- | An IO-type for ACME primitives.
Errors from the ACME server are returned as values (see 'AcmeError').
As we iterate on this lib, this type may change to become a monad-stack/mtl-mashup.
-}
type AcmePrim a = IO (Either AcmeError a)

{- | An object carrying all functions to generate a single authorization from a
single order with a DNS challenge.
-}
data AcmeSingle = AcmeSingle
    { dir :: Directory
    -- ^ directory for the Server
    , nonces :: Nonce.Fetcher
    -- ^ an object to generate new nonces for this ACME server, saving found nonces opportunistically
    , pollOrder :: AcmePrim OrderInspected
    -- ^ fetches the status of an order
    , fetchAuthorization :: AcmePrim AuthorizationInspected
    -- ^ fetches the authorization, this function is called by prepareAcmeOrder so you may not need to inspect authorization yourself
    , proof :: (Token, KeyAuthorization, ValidationProof)
    -- ^ the validation proof (i.e., the value to set in DNS records and so on)
    , replyChallenge :: AcmePrim ChallengeAttempted
    -- ^ tells the server it can validates the challenge (i.e., after writing the proof in some DNS record)
    , pollChallenge :: AcmePrim ChallengeAttempted
    -- ^ fetches the status of a challenge (mainly to know if the server has validated the challenge)
    , finalizeOrder :: AcmePrim OrderFinalized
    -- ^ finalize the order (i.e, effectively sends the CSR to the server)
    , fetchCertificate :: Url "certificate" -> AcmePrim Certificate
    -- ^ fetch the signed certificate, the URL comes from a OrderInspected (see readOrderInspected)
    }

data PrepareStep
    = Starting
    | GotDirectory Directory
    | GettingNonce
    | GotAccount AccountCreated
    | GotOrder OrderCreated
    | GotAuthorization AuthorizationInspected

type MatchChallenge = Challenge "challenge-unspecified" -> Bool

{- | Runs the first steps of the ACME dance: up to the point where the client
has to prove it controls the identifier in the order.

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
    authUrl <- expect "no authorization in order" orderCreated $ safeHead . authorizations =<< readOrderCreated orderCreated
    step $ GotOrder orderCreated

    -- poller for order
    orderUrl <- expect "no order location" orderCreated $ readOrderUrl orderCreated
    let fpollOrder = saveNonce nf (nonceify $ postGetOrder jwk orderUrl kid)

    -- read authorization's dns challenge
    let ffetchAuthorization = saveNonce nf (nonceify $ postGetAuthorization jwk kid authUrl)
    authorizationInspected <- ExceptT $ ffetchAuthorization
    step $ GotAuthorization authorizationInspected
    challenge <- expect "no matching challenge in authorization" authorizationInspected $ List.find matchChallenge . challenges =<< readAuthorization authorizationInspected

    -- challenge validation proof
    let tok = challenge.token
    let keyAuth = keyAuthorization tok jwk
    let proofVal = sha256digest keyAuth

    -- read authorization's dns challenge
    let freplyChallenge = saveNonce nf (nonceify $ postReplyChallenge jwk kid challenge)
    let fpollChallenge = saveNonce nf (nonceify $ postGetChallenge jwk kid challenge)

    -- finalize order
    finalizeOrderUrl <- expect "no finalize url in order" orderCreated $ fmap finalize $ readOrderCreated orderCreated
    let ffinalizeOrder = saveNonce nf (nonceify $ postFinalizeOrder jwk kid finalizeOrderUrl (Finalize csr1))

    -- fetch certificate (at last)
    let ffetchCertificate certificateUrl = saveNonce nf (nonceify $ postGetCertificate jwk kid certificateUrl)

    pure $ AcmeSingle acmeDir nf fpollOrder ffetchAuthorization (tok, keyAuth, proofVal) freplyChallenge fpollChallenge ffinalizeOrder ffetchCertificate
  where
    step :: PrepareStep -> ExceptT AcmeError IO ()
    step = liftIO . handleStep

    -- turns a failed lookup in a (successful) response into an error
    expect :: (Coercible rsp Response) => Text -> rsp -> Maybe x -> ExceptT AcmeError IO x
    expect what rsp = maybe (throwE $ UnexpectedResponse what (coerce rsp)) pure

    safeHead :: [x] -> Maybe x
    safeHead [] = Nothing
    safeHead (x : _) = Just x
