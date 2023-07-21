{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE FlexibleContexts #-}

-- | Almost all ACME API Calls require a Nonce to prevent replayability of
-- requests.
-- Most API Calls return a Nonce for the next request.
-- Client should re-use these Nonce to avoid overloading the server.
-- This module provide helpers to deal with this requirement.
module Acme.NotAJoke.Api.Nonce where

import Data.IORef (newIORef, atomicModifyIORef, writeIORef)
import Data.Coerce (coerce, Coercible)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding
import Data.ByteString.Lazy (ByteString)
import Data.Aeson (FromJSON(..), ToJSON(..))
import qualified Network.Wreq as Wreq
import Control.Lens hiding ((.=))

import Acme.NotAJoke.Api.Endpoint

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


data Fetcher = Fetcher {
    produce :: IO (Maybe Nonce)
  , set :: Nonce -> IO ()
  , fetchNewNonce :: IO (Maybe Nonce)
  }

fetcher :: IO (Maybe Nonce) -> IO Fetcher
fetcher fetch = do
    ref <- newIORef Nothing
    pure $ Fetcher (go ref) (writeIORef ref . Just) fetch
  where
    go ref = do
      val <- atomicModifyIORef ref (\x -> (Nothing,x))
      case val of
        Nothing -> fetch
        (Just x) -> pure (Just x)

saveResponseNonce :: forall a. Coercible a (Wreq.Response ByteString) => Fetcher -> a -> IO ()
saveResponseNonce nonceFetcher rsp =
  maybe (pure ()) (nonceFetcher.set) (responseNonce rsp)

saveNonce :: forall a. Coercible a (Wreq.Response ByteString) => Fetcher -> IO (Maybe a) -> IO (Maybe a)
saveNonce nonceFetcher apiCall = do
  obj <- apiCall
  maybe (pure ()) (saveResponseNonce nonceFetcher) obj
  pure obj
