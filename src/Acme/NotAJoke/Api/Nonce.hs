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

-- | An anti-replay nonce, valid for one request.
newtype Nonce = Nonce Text
    deriving (Show, FromJSON, ToJSON)

-- | Asks the server for a fresh nonce (at the @newNonce@ endpoint of the directory).
getNonce :: Endpoint "newNonce" -> IO (Either AcmeError Nonce)
getNonce ep = do
    r <- head_ ep
    pure $ readNonce =<< r
  where
    readNonce rsp =
        maybe (Left $ UnexpectedResponse "no replay-nonce header" rsp) Right $
            rawResponseNonce rsp

-- | Lookup the nonce of a response, in its @Replay-Nonce@ header.
rawResponseNonce :: Response -> Maybe Nonce
rawResponseNonce rsp =
    Nonce . Encoding.decodeUtf8 <$> responseHeader "replay-nonce" rsp

-- | Same as 'rawResponseNonce' for the newtypes wrapping a 'Response'.
responseNonce :: forall a. (Coercible a Response) => a -> Maybe Nonce
responseNonce = rawResponseNonce . coerce

{- | A source of nonces which keeps the last nonce returned by the server and
fetches a fresh one only when it has none.
-}
data Fetcher = Fetcher
    { produce :: IO (Either AcmeError Nonce)
    -- ^ returns the saved nonce (forgetting it), or fetches a fresh one
    , set :: Nonce -> IO ()
    -- ^ saves a nonce for the next call to 'produce'
    , fetchNewNonce :: IO (Either AcmeError Nonce)
    -- ^ fetches a fresh nonce, ignoring the saved one
    }

-- | Builds a 'Fetcher' from a way to fetch fresh nonces (e.g., 'getNonce').
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

-- | Saves the nonce of a response (if any) in a 'Fetcher'.
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
