{- | ACME challenges (RFC-8555 sections 7.5 and 8, RFC-8737).

An authorization offers several challenges, each a way to prove control of
the identifier; the client completes one of them:

1. pick a challenge (e.g., with 'isDNS01', 'isHTTP01' or 'isTLSALPN01')
2. compute the proof from its 'Token' and the account key (see
   "Acme.NotAJoke.Api.Validation"), and publish it: a TXT record for DNS-01,
   a file served over HTTP for HTTP-01, a certificate served over TLS for
   TLS-ALPN-01
3. tell the server the proof is in place ('postReplyChallenge'), the server
   then checks it
4. poll the challenge ('postGetChallenge'), or the order, until it is valid
   (or invalid)

"Acme.NotAJoke.Dancer" runs these steps for all the authorizations of an
order, calling your code at step 2.
-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Acme.NotAJoke.Api.Challenge where

import Data.Aeson (FromJSON (..), Value (..), encode, withObject, withText, (.:), (.:?))
import Data.Coerce (coerce)
import Data.Text (Text)
import Data.Time.Clock (UTCTime)

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Field
import Acme.NotAJoke.Api.JWS
import Acme.NotAJoke.Api.Nonce

-- | RFC-defined Challenge types.
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
            _ -> pure $ ChallengeUnspec txt

-- | RFC-defined Challenge statuses.
data ChallengeStatus
    = -- | challenge is pending (the client should take action)
      ChallengePending
    | -- | challenge is processing (the server should take action)
      ChallengeProcessing
    | -- | challenge has succeeded
      ChallengeValid
    | -- | challenge has failed, timed out etc.
      ChallengeInvalid
    deriving (Show, Eq, Ord)

instance FromJSON ChallengeStatus where
    parseJSON = withText "ChallengeStatus" $ \txt ->
        case txt of
            "pending" -> pure ChallengePending
            "processing" -> pure ChallengeProcessing
            "valid" -> pure ChallengeValid
            "invalid" -> pure ChallengeInvalid
            _ -> fail $ "invalid challenge status:" <> show txt

{- | RFC-defined Challenge resources, the @token@ depending on the state @a@
(only @\"challenge-unspecified\"@ for now, where the token is present).

The original JSON object is kept in '_sourceObject', for the fields of
challenge types this library does not know about.
-}
data Challenge a
    = Challenge
    { type_ :: ChallengeType
    , url :: Url "challenge"
    , status :: ChallengeStatus
    , validated :: Maybe UTCTime
    , error :: Maybe Problem
    , --
      token :: Field a "token" Token
    , --
      _sourceObject :: Value -- for extensibility
    }

type instance Field "challenge-unspecified" "token" x = x

{- | Predicate useful to locate DNS-01 challenges when multiple challenges can
validate an Authorization.
-}
isDNS01 :: Challenge "challenge-unspecified" -> Bool
isDNS01 challenge = challenge.type_ == ChallengeDNS01

{- | Predicate useful to locate HTTP-01 challenges when multiple challenges can
validate an Authorization.

Note that HTTP-01 challenges cannot validate wildcard identifiers.
-}
isHTTP01 :: Challenge "challenge-unspecified" -> Bool
isHTTP01 challenge = challenge.type_ == ChallengeHTTP01

{- | Predicate useful to locate TLS-ALPN-01 challenges (RFC-8737) when multiple
challenges can validate an Authorization.

Note that TLS-ALPN-01 challenges cannot validate wildcard identifiers.
-}
isTLSALPN01 :: Challenge "challenge-unspecified" -> Bool
isTLSALPN01 challenge = challenge.type_ == ChallengeTLSALPN01

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

{- | An opaque Token that is required in ACME challenges to prove that you
control a given resource.
-}
newtype Token = Token Text
    deriving (Eq, Ord, FromJSON)

-- | The response of the server to 'postReplyChallenge' or 'postGetChallenge'.
newtype ChallengeAttempted = ChallengeAttempted Response
    deriving (Show)

{- | Notify the ACME server that you are ready to reply a challenge.

For instance, after installing the required DNS-records.
-}
postReplyChallenge :: JWS.JWK -> KID -> Challenge a -> Nonce -> IO (Either AcmeError ChallengeAttempted)
postReplyChallenge jwk kid challenge nonce = do
    ebody <- (kidSign jwk ep kid nonce $ encode emptyObject)
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap ChallengeAttempted e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)

-- | Query the ACME server about the status of a given challenge.
postGetChallenge :: JWS.JWK -> KID -> Challenge a -> Nonce -> IO (Either AcmeError ChallengeAttempted)
postGetChallenge jwk kid challenge nonce = do
    ebody <- (kidSign jwk ep kid nonce "")
    case ebody of
        Right body -> do
            e <- postJose ep $ encode body
            pure $ fmap ChallengeAttempted e
        Left err -> do
            pure $ Left $ SigningFailed err
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)
