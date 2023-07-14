{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
module Acme.NotAJoke.Challenge where

import Data.Coerce (coerce)
import Data.Text (Text)
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), withText, withObject,encode, (.:), (.:?), Value(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))
import Data.Time.Clock (UTCTime)

import qualified Crypto.JOSE.JWS as JWS

import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Field
import Acme.NotAJoke.Nonce
import Acme.NotAJoke.JWS

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
                  _     -> pure $ ChallengeUnspec txt

-- | RFC-defined Challenge statuses.
data ChallengeStatus
  = ChallengePending
  -- ^ challenge is pending (the client should take action)
  | ChallengeProcessing
  -- ^ challenge is processing (the server should take action)
  | ChallengeValid
  -- ^ challenge has succeeded
  | ChallengeInvalid
  -- ^ challenge has failed, timed out etc.
  deriving (Show, Eq, Ord)

instance FromJSON ChallengeStatus where
  parseJSON = withText "ChallengeStatus" $ \txt ->
                case txt of
                  "pending" -> pure ChallengePending
                  "processing" -> pure ChallengeProcessing
                  "valid" -> pure ChallengeValid
                  "invalid" -> pure ChallengeInvalid
                  _     -> fail $ "invalid challenge status:" <> show txt

-- | RFC-defined Challenge resources.
data Challenge a
  = Challenge
  { type_ :: ChallengeType
  , url :: Url "challenge"
  , status :: ChallengeStatus
  , validated :: Maybe UTCTime
  , error :: Maybe Problem
  --
  , token :: Field a "token" Token
  --
  , _sourceObject :: Value -- for extensibility
  }

type instance Field "challenge-unspecified" "token" x = x

-- | Predicate useful to locate DNS-01 challenges when multiple challenges can
-- validate an Authorization.
isDNS01 :: Challenge "challenge-unspecified" -> Bool
isDNS01 challenge = challenge.type_ == ChallengeDNS01

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

-- | An opaque Token that is required in ACME challenges to prove that you
-- control a given resource.
newtype Token = Token Text
  deriving (Eq, Ord, FromJSON)

newtype ChallengeAttempted = ChallengeAttempted (Wreq.Response ByteString)
  deriving (Show)

-- | Notify the ACME server that you are ready to reply a challenge.
-- 
-- For instance, after installing the required DNS-records.
postReplyChallenge :: JWS.JWK -> KID -> Nonce -> Challenge a -> IO (Maybe ChallengeAttempted)
postReplyChallenge jwk kid nonce challenge = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce $ encode emptyObject)
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ ChallengeAttempted e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)

-- | Query the ACME server about the status of a given challenge.
postGetChallenge :: JWS.JWK -> KID -> Nonce -> Challenge a -> IO (Maybe ChallengeAttempted)
postGetChallenge jwk kid nonce challenge = do
  let opts = Wreq.defaults & Wreq.header "Content-Type" .~ ["application/jose+json"]
  ebody <- (kidSign jwk ep kid nonce "")
  case ebody of
    Right body -> do
      e <- Wreq.postWith opts (wrequrl ep) $ encode body
      pure $ Just $ ChallengeAttempted e
    Left err -> do
      print err
      pure Nothing
  where
    ep :: Endpoint "authorization"
    ep = coerce (challenge.url)
