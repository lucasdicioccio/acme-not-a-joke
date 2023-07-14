{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE FlexibleContexts #-}

-- | Almost all ACME API Calls require a Nonce to prevent replayability of
-- requests.
-- Most API Calls return a Nonce for the next request.
-- Client should re-use these Nonce to avoid overloading the server.
-- This module provide helpers to deal with this requirement.
module Acme.NotAJoke.Nonce where

import Data.Coerce (coerce, Coercible)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import Acme.NotAJoke.Endpoint

newtype Nonce = Nonce Text
  deriving (Show, FromJSON, ToJSON)

getNonce :: Endpoint "newNonce" -> IO (Maybe Nonce)
getNonce ep = do
  r <- Wreq.head_ (wrequrl ep)
  pure $ responseNonceWreq r
  where

responseNonceWreq :: forall a. Wreq.Response a -> Maybe Nonce
responseNonceWreq r =
  r ^? Wreq.responseHeader "replay-nonce" . to Encoding.decodeUtf8 . to Nonce

responseNonceWreqBS :: Wreq.Response ByteString -> Maybe Nonce
responseNonceWreqBS = responseNonceWreq

responseNonce :: forall a. Coercible a (Wreq.Response ByteString) => a -> Maybe Nonce
responseNonce = responseNonceWreqBS . coerce
