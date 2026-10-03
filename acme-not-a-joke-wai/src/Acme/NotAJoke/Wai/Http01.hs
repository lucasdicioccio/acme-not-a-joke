{- | Serves HTTP-01 challenges (RFC-8555 section 8.3) from a wai application.

The ACME server validates an HTTP-01 challenge by fetching
@http:\/\/{domain}\/.well-known\/acme-challenge\/{token}@ (on port 80) and
expects the key authorization as a response.

This module provides a 'ChallengeStore' shared between two parties:

* a 'Middleware' ('http01Middleware') answering the requests of the ACME server
* a dance ('runAcmeDance_http01_wai') or a step handler ('http01Steps') adding
  the key authorization before the ACME server is told to validate the
  challenge and removing it once the dance is over

HTTP-01 challenges cannot validate wildcard identifiers.
-}
module Acme.NotAJoke.Wai.Http01 (
    -- * store
    ChallengeStore,
    newChallengeStore,
    insertChallenge,
    deleteChallenge,
    lookupChallenge,
    listChallenges,

    -- * wai
    http01Middleware,
    challengeResponse,

    -- * dance
    runAcmeDance_http01_wai,
    http01Steps,
) where

import Control.Exception (finally)
import qualified Data.ByteString.Lazy as LByteString
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text.Encoding as Encoding
import Network.HTTP.Types (hContentType, methodGet, status200)
import Network.Wai (Middleware, Response, pathInfo, requestMethod, responseLBS)

import Acme.NotAJoke.Api.Challenge (Token (..))
import Acme.NotAJoke.Api.Validation (KeyAuthorization (..))
import Acme.NotAJoke.Dancer (AcmeDancer (..), DanceStep (..), runAcmeDance_http01)

{- | The challenges being served: the key authorization to reply for each
token.

A same store can be shared by concurrent dances.
-}
newtype ChallengeStore = ChallengeStore (IORef (Map Token KeyAuthorization))

-- | Creates an empty store.
newChallengeStore :: IO ChallengeStore
newChallengeStore = ChallengeStore <$> newIORef Map.empty

-- | Starts serving the key authorization of a token.
insertChallenge :: ChallengeStore -> Token -> KeyAuthorization -> IO ()
insertChallenge (ChallengeStore ref) tok keyAuth =
    atomicModifyIORef' ref (\m -> (Map.insert tok keyAuth m, ()))

-- | Stops serving the key authorization of a token.
deleteChallenge :: ChallengeStore -> Token -> IO ()
deleteChallenge (ChallengeStore ref) tok =
    atomicModifyIORef' ref (\m -> (Map.delete tok m, ()))

-- | Looks up the key authorization of a token.
lookupChallenge :: ChallengeStore -> Token -> IO (Maybe KeyAuthorization)
lookupChallenge (ChallengeStore ref) tok =
    Map.lookup tok <$> readIORef ref

-- | The tokens currently served.
listChallenges :: ChallengeStore -> IO [Token]
listChallenges (ChallengeStore ref) =
    Map.keys <$> readIORef ref

{- | Answers @GET \/.well-known\/acme-challenge\/{token}@ with the key
authorization when the token is in the store.

Any other request, including requests for a token that is not in the store, is
passed to the wrapped application.

The ACME server performs its request over HTTP on port 80. Hence the
middleware should wrap whatever redirects HTTP requests to HTTPS.
-}
http01Middleware :: ChallengeStore -> Middleware
http01Middleware store app req respond =
    case pathInfo req of
        [".well-known", "acme-challenge", tok]
            | requestMethod req == methodGet -> do
                found <- lookupChallenge store (Token tok)
                case found of
                    Just keyAuth -> respond $ challengeResponse keyAuth
                    Nothing -> app req respond
        _ -> app req respond

-- | The response expected by the ACME server for an HTTP-01 challenge.
challengeResponse :: KeyAuthorization -> Response
challengeResponse (KeyAuthorization keyAuth) =
    responseLBS
        status200
        [(hContentType, "application/octet-stream")]
        (LByteString.fromStrict $ Encoding.encodeUtf8 keyAuth)

{- | Runs the dance with an HTTP-01 challenge served from the store.

The key authorization is added to the store before the 'handleStep' of the
dancer sees the 'Validation' step, and is removed when the dance is over
(whether the dance succeeds, fails, or throws an exception).

The 'handleStep' of the dancer still is responsible for the other steps (e.g.,
waiting between two polls and storing the certificate).
-}
runAcmeDance_http01_wai :: ChallengeStore -> AcmeDancer -> IO ()
runAcmeDance_http01_wai store dancer = do
    served <- newIORef []
    runAcmeDance_http01 (dancer{handleStep = serveSteps store served dancer.handleStep})
        `finally` stopServing store served

{- | Wraps a step handler to serve HTTP-01 challenges from the store, for use
with 'runAcmeDance_http01' or with a custom matcher.

The key authorization is added to the store before the wrapped handler sees the
'Validation' step, and is removed after the wrapped handler has seen the last
step of the dance ('Done', 'InvalidOrder', 'OtherError' or 'AcmeFailure').

The key authorization is not removed if the dance throws an exception, see
'runAcmeDance_http01_wai' for a variant handling exceptions.
-}
http01Steps :: ChallengeStore -> (DanceStep -> IO ()) -> IO (DanceStep -> IO ())
http01Steps store handler = do
    served <- newIORef []
    pure (serveSteps store served handler)

-- | Step handler keeping track of the tokens it added to the store.
serveSteps :: ChallengeStore -> IORef [Token] -> (DanceStep -> IO ()) -> DanceStep -> IO ()
serveSteps store served handler step =
    case step of
        Validation (tok, keyAuth, _) -> do
            atomicModifyIORef' served (\toks -> (tok : toks, ()))
            insertChallenge store tok keyAuth
            handler step
        Done _ _ -> final
        InvalidOrder _ -> final
        OtherError _ -> final
        AcmeFailure _ -> final
        WaitingForValidation _ -> handler step
        OrderIsFinalized _ -> handler step
        ValidOrder _ -> handler step
        Prepare _ -> handler step
  where
    final = handler step `finally` stopServing store served

-- | Removes the tokens added by a step handler.
stopServing :: ChallengeStore -> IORef [Token] -> IO ()
stopServing store served = do
    toks <- atomicModifyIORef' served (\toks -> ([], toks))
    mapM_ (deleteChallenge store) toks
