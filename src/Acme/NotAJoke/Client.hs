{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

module Acme.NotAJoke.Client where

import Data.Maybe (fromJust)
import qualified Data.List as List

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Nonce as Nonce
import Acme.NotAJoke.Api.Order
import Acme.NotAJoke.Api.Authorization
import Acme.NotAJoke.Api.Challenge
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Certificate
import Acme.NotAJoke.Api.Validation

-- | An IO-type for ACME primitives.
-- As we iterate on this lib, this type may change to become a monad-stack/mtl-mashup.
type AcmePrim a = IO (Maybe a)

-- | An object carrying all functions to generate a single authorization from a
-- single order with a DNS challenge.
data AcmeSingle = AcmeSingle
  { dir                :: Directory
  -- ^ directory for the Server
  , nonces             :: Nonce.Fetcher
  -- ^ an object to generate new nonces for this ACME server, saving found nonces opportunistically
  , pollOrder          :: AcmePrim OrderInspected
  -- ^ fetches the status of an order
  , fetchAuthorization :: AcmePrim AuthorizationInspected
  -- ^ fetches the authorization, this function is called by prepareAcmeOrder so you may not need to inspect authorization yourself
  , proof              :: (Token, KeyAuthorization, ValidationProof)
  -- ^ the validation proof (i.e., the value to set in DNS records and so on)
  , replyChallenge     :: AcmePrim ChallengeAttempted
  -- ^ tells the server it can validates the challenge (i.e., after writing the proof in some DNS record)
  , pollChallenge      :: AcmePrim ChallengeAttempted
  -- ^ fetches the status of a challenge (mainly to know if the server has validated the challenge)
  , finalizeOrder      :: AcmePrim OrderFinalized
  -- ^ finalize the order (i.e, effectively sends the CSR to the server)
  , fetchCertificate   :: Url "certificate" -> AcmePrim Certificate
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

-- TODO:
-- * step for errors
-- * return shortcuts in handleStep function
prepareAcmeOrder
  :: BaseUrl
  -> JWK.JWK
  -> Account "account-fetch"
  -> CSR
  -> Order "order-create"
  -> MatchChallenge
  -> (PrepareStep -> IO ())
  -> IO AcmeSingle
prepareAcmeOrder baseurl jwk account csr1 order matchChallenge handleStep = do
  handleStep $ Starting

  -- unauthenticated info
  acmeDir <- fetchDirectory (directory baseurl)
  nf <- fetcher (handleStep GettingNonce >> getNonce acmeDir.newNonce)
  let mknonce = nf.produce
  let nonceify = fromJust <$> mknonce
  handleStep $ GotDirectory acmeDir

  -- fetch account
  nonce1 <- nonceify
  Just accountCreated <- saveNonce nf (postFetchAccount jwk acmeDir.newAccount nonce1 account)
  let (Just kid) = readKID accountCreated
  handleStep $ GotAccount accountCreated

  -- prepare new order
  nonce2 <- nonceify
  Just orderCreated <- saveNonce nf (postNewOrder jwk acmeDir.newOrder kid nonce2 order)
  let Just authUrl = fmap (head . authorizations) $ readOrderCreated orderCreated
  handleStep $ GotOrder orderCreated

  -- poller for order
  let Just orderUrl = readOrderUrl orderCreated
  let fpollOrder = saveNonce nf (postGetOrder jwk orderUrl kid =<< nonceify)

  -- read authorization's dns challenge 
  let ffetchAuthorization = saveNonce nf (postGetAuthorization jwk kid authUrl =<< nonceify)
  Just authorizationInspected <- ffetchAuthorization
  handleStep $ GotAuthorization authorizationInspected
  let Just challenge = List.find matchChallenge . challenges =<< readAuthorization authorizationInspected

  -- challenge validation proof
  let tok = challenge.token
  let keyAuth  = keyAuthorization tok jwk
  let proofVal = sha256digest keyAuth

  -- read authorization's dns challenge 
  let freplyChallenge = saveNonce nf (postReplyChallenge jwk kid challenge =<< nonceify)
  let fpollChallenge = saveNonce nf (postGetChallenge jwk kid challenge =<< nonceify)

  -- finalize order
  let Just finalizeOrderUrl = fmap finalize $ readOrderCreated orderCreated
  let ffinalizeOrder = saveNonce nf (postFinalizeOrder jwk kid finalizeOrderUrl (Finalize csr1) =<< nonceify)

  -- fetch certificate (at last)
  let ffetchCertificate certificateUrl = saveNonce nf (postGetCertificate jwk kid certificateUrl =<< nonceify)

  pure $ AcmeSingle acmeDir nf fpollOrder ffetchAuthorization (tok, keyAuth, proofVal) freplyChallenge fpollChallenge ffinalizeOrder ffetchCertificate
