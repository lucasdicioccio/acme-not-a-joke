{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE FlexibleContexts #-}

module Acme.NotAJoke.Nonce where

import Data.Coerce (coerce, Coercible)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import Acme.NotAJoke.Endpoint

-- NONCE

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

