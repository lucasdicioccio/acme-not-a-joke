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

doGenJWK :: IO JWK.JWK
doGenJWK = JWK.genJWK (JWK.RSAGenParam (4096 `div` 8))

doLoadJWK :: FilePath -> IO (Maybe JWK.JWK)
doLoadJWK = fmap decode . LBS.readFile

-- Bundle Acme

type AcmePrim a = Nonce -> IO (Maybe a)
data Acme = Acme
  { dir                :: Directory
  , newNonce           :: IO (Maybe Nonce)
  , unusedNonce        :: Nonce
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
orderAcme baseurl jwk account csr1 order = do
  -- unauthenticated info
  acmeDir <- fetchDirectory (directory baseurl)
  let mknonce = getNonce acmeDir.newNonce

  -- fetch account
  Just nonce1 <- mknonce
  Just accountCreated <- postFetchAccount jwk acmeDir.newAccount nonce1 account
  let (Just nonce2) = responseNonce accountCreated
  let (Just kid) = readKID accountCreated

  -- prepare new order
  Just orderCreated <- postNewOrder jwk acmeDir.newOrder kid nonce2 order
  let (Just nonce3) = responseNonce orderCreated
  let Just authUrl = fmap (head . authorizations) $ readOrderCreated orderCreated

  -- poller for order
  let Just orderUrl = readOrderUrl orderCreated
  let fpollOrder nonce = postGetOrder jwk orderUrl kid nonce

  -- read authorization's dns challenge 
  let ffetchAuthorization nonce = postGetAuthorization jwk kid nonce authUrl
  Just authorizationInspected <- ffetchAuthorization nonce3
  let (Just nonce4) = responseNonce authorizationInspected
  let Just challenge = List.find isDNS01 . challenges =<< readAuthorization authorizationInspected

  -- read authorization's dns challenge 
  let freplyChallenge nonce = postReplyChallenge jwk kid nonce challenge
  let fpollChallenge nonce = postGetChallenge jwk kid nonce challenge

  -- challenge validation proof
  let fproof = sha256digest (keyAuthorization (token challenge) jwk)

  -- finalize order
  let Just finalizeOrderUrl = fmap finalize $ readOrderCreated orderCreated
  let ffinalizeOrder nonce = postFinalizeOrder jwk kid nonce finalizeOrderUrl (Finalize csr1)

  -- fetch certificate (at last)
  let ffetchCertificate certificateUrl nonce = postGetCertificate jwk kid nonce certificateUrl

  pure $ Acme acmeDir mknonce nonce4 fpollOrder ffetchAuthorization fproof freplyChallenge fpollChallenge ffinalizeOrder ffetchCertificate

letsencryptv2 :: BaseUrl
letsencryptv2 = "https://acme-v02.api.letsencrypt.org/"

staging_letsencryptv2 :: BaseUrl
staging_letsencryptv2 = "https://acme-staging-v02.api.letsencrypt.org/"
