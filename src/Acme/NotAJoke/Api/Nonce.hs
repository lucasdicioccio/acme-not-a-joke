{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{- | Almost all ACME API Calls require a Nonce to prevent replayability of
requests.
Most API Calls return a Nonce for the next request.
Client should re-use these Nonce to avoid overloading the server.
This module provide helpers to deal with this requirement.
-}
module Acme.NotAJoke.Api.Nonce where

import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Coerce (Coercible, coerce)
import Data.IORef (atomicModifyIORef, newIORef, writeIORef)
import Data.Text (Text)
import qualified Data.Text.Encoding as Encoding

import Acme.NotAJoke.Api.Endpoint

newtype Nonce = Nonce Text
    deriving (Show, FromJSON, ToJSON)

getNonce :: Endpoint "newNonce" -> IO (Either AcmeError Nonce)
getNonce ep = do
    r <- head_ ep
    pure $ readNonce =<< r
  where
    readNonce rsp =
        maybe (Left $ UnexpectedResponse "no replay-nonce header" rsp) Right $
            rawResponseNonce rsp

rawResponseNonce :: Response -> Maybe Nonce
rawResponseNonce rsp =
    Nonce . Encoding.decodeUtf8 <$> responseHeader "replay-nonce" rsp

responseNonce :: forall a. (Coercible a Response) => a -> Maybe Nonce
responseNonce = rawResponseNonce . coerce

data Fetcher = Fetcher
    { produce :: IO (Either AcmeError Nonce)
    , set :: Nonce -> IO ()
    , fetchNewNonce :: IO (Either AcmeError Nonce)
    }

fetcher :: IO (Either AcmeError Nonce) -> IO Fetcher
fetcher fetch = do
    ref <- newIORef Nothing
    pure $ Fetcher (go ref) (writeIORef ref . Just) fetch
  where
    go ref = do
        val <- atomicModifyIORef ref (\x -> (Nothing, x))
        case val of
            Nothing -> fetch
            (Just x) -> pure (Right x)

saveResponseNonce :: forall a. (Coercible a Response) => Fetcher -> a -> IO ()
saveResponseNonce nonceFetcher rsp =
    maybe (pure ()) (nonceFetcher.set) (responseNonce rsp)

{- | Saves the nonce found in the response of an API call.
Error responses from the server carry a fresh nonce as well, which we save too.
-}
saveNonce :: forall a. (Coercible a Response) => Fetcher -> IO (Either AcmeError a) -> IO (Either AcmeError a)
saveNonce nonceFetcher apiCall = do
    obj <- apiCall
    case obj of
        Right rsp -> saveResponseNonce nonceFetcher rsp
        Left err -> maybe (pure ()) (saveResponseNonce nonceFetcher) (errorResponse err)
    pure obj
