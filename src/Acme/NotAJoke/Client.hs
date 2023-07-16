{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

module Acme.NotAJoke.Client where

import qualified Data.ByteString.Lazy as LBS
import Data.Aeson (decode)
import qualified Data.List as List

import qualified Crypto.JOSE.JWK as JWK

import Acme.NotAJoke.Account
import Acme.NotAJoke.Directory
import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.Order
import Acme.NotAJoke.Authorization
import Acme.NotAJoke.Challenge
import Acme.NotAJoke.CSR
import Acme.NotAJoke.Certificate
import Acme.NotAJoke.Validation

-- | Generates and RSA-4096 bits key.
doGenJWK :: IO JWK.JWK
doGenJWK = JWK.genJWK (JWK.RSAGenParam (4096 `div` 8))

-- | Loads a JWK from a file.
doLoadJWK :: FilePath -> IO (Maybe JWK.JWK)
doLoadJWK = fmap decode . LBS.readFile

-- | An IO-type for ACME primitives.
-- As we iterate on this lib, this type may change to become a monad-stack/mtl-mashup.
type AcmePrim a = Nonce -> IO (Maybe a)

-- | An object carrying all functions to generate a single authorization from a
-- single order with a DNS challenge.
data AcmeSingle = AcmeSingle
  { dir                :: Directory
  -- ^ directory for the Server
  , newNonce           :: IO (Maybe Nonce)
  -- ^ an action to generate a new nonce for this ACME server
  , unusedNonce        :: Nonce
  -- ^ the latest unused nonce after initialization (valid only once, hence moderately useful)
  , pollOrder          :: AcmePrim OrderInspected
  -- ^ fetches the status of an order
  , fetchAuthorization :: AcmePrim AuthorizationInspected
  -- ^ fetches the authorization, this function is called by prepareAcmeOrder so you may not need to inspect authorization yourself
  , proof              :: ValidationProof
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

prepareAcmeOrder :: BaseUrl -> JWK.JWK -> Account "account-fetch" -> CSR -> Order "order-create" -> (PrepareStep -> IO ()) -> IO AcmeSingle
prepareAcmeOrder baseurl jwk account csr1 order handleStep = do
  handleStep $ Starting

  -- unauthenticated info
  acmeDir <- fetchDirectory (directory baseurl)
  let mknonce = handleStep GettingNonce >> getNonce acmeDir.newNonce
  handleStep $ GotDirectory acmeDir

  -- fetch account
  Just nonce1 <- mknonce
  Just accountCreated <- postFetchAccount jwk acmeDir.newAccount nonce1 account
  let (Just nonce2) = responseNonce accountCreated
  let (Just kid) = readKID accountCreated
  handleStep $ GotAccount accountCreated

  -- prepare new order
  Just orderCreated <- postNewOrder jwk acmeDir.newOrder kid nonce2 order
  let (Just nonce3) = responseNonce orderCreated
  let Just authUrl = fmap (head . authorizations) $ readOrderCreated orderCreated
  handleStep $ GotOrder orderCreated

  -- poller for order
  let Just orderUrl = readOrderUrl orderCreated
  let fpollOrder nonce = postGetOrder jwk orderUrl kid nonce

  -- read authorization's dns challenge 
  let ffetchAuthorization nonce = postGetAuthorization jwk kid nonce authUrl
  Just authorizationInspected <- ffetchAuthorization nonce3
  handleStep $ GotAuthorization authorizationInspected
  let (Just nonce4) = responseNonce authorizationInspected
  let Just challenge = List.find isDNS01 . challenges =<< readAuthorization authorizationInspected

  -- challenge validation proof
  let proofVal = sha256digest (keyAuthorization (token challenge) jwk)

  -- read authorization's dns challenge 
  let freplyChallenge nonce = postReplyChallenge jwk kid nonce challenge
  let fpollChallenge nonce = postGetChallenge jwk kid nonce challenge

  -- finalize order
  let Just finalizeOrderUrl = fmap finalize $ readOrderCreated orderCreated
  let ffinalizeOrder nonce = postFinalizeOrder jwk kid nonce finalizeOrderUrl (Finalize csr1)

  -- fetch certificate (at last)
  let ffetchCertificate certificateUrl nonce = postGetCertificate jwk kid nonce certificateUrl

  pure $ AcmeSingle acmeDir mknonce nonce4 fpollOrder ffetchAuthorization proofVal freplyChallenge fpollChallenge ffinalizeOrder ffetchCertificate

-- Base URL for Let'sEncrypt staging.
staging_letsencryptv2 :: BaseUrl
staging_letsencryptv2 = "https://acme-staging-v02.api.letsencrypt.org/"

-- Base URL for Let'sEncrypt production.
letsencryptv2 :: BaseUrl
letsencryptv2 = "https://acme-v02.api.letsencrypt.org/"
