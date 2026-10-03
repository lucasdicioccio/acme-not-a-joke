module Main (main) where

import Control.Exception (ErrorCall (..), throwIO, try)
import Control.Monad (unless)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as LByteString
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Network.HTTP.Types (Status, methodPost, status200, status404)
import Network.Wai (Application, Request, Response, defaultRequest, pathInfo, requestMethod, responseLBS, responseStatus, responseToStream)
import System.Exit (exitFailure)

import Acme.NotAJoke.Api.Challenge (Token (..))
import Acme.NotAJoke.Api.Validation (KeyAuthorization (..), sha256digest)
import Acme.NotAJoke.Dancer (DanceStep (..))
import Acme.NotAJoke.Wai.Http01

main :: IO ()
main = do
    middlewareServesKnownTokens
    stepsFillAndClearStore
    stepsClearStoreWhenHandlerThrows
    putStrLn "ok"

token1 :: Token
token1 = Token "token-1"

keyAuth1 :: KeyAuthorization
keyAuth1 = KeyAuthorization "token-1.thumbprint"

validation1 :: DanceStep
validation1 = Validation (token1, keyAuth1, sha256digest keyAuth1)

-- | The application behind the middleware.
fallback :: Application
fallback _ respond = respond $ responseLBS status404 [] "fallback"

challengeRequest :: Request
challengeRequest = defaultRequest{pathInfo = [".well-known", "acme-challenge", "token-1"]}

middlewareServesKnownTokens :: IO ()
middlewareServesKnownTokens = do
    store <- newChallengeStore
    let app = http01Middleware store fallback

    before <- run app challengeRequest
    check "unknown token is passed to the application" (before == (status404, "fallback"))

    insertChallenge store token1 keyAuth1
    found <- run app challengeRequest
    check "known token gets the key authorization" (found == (status200, "token-1.thumbprint"))

    posted <- run app challengeRequest{requestMethod = methodPost}
    check "non-GET is passed to the application" (posted == (status404, "fallback"))

    other <- run app defaultRequest{pathInfo = [".well-known", "acme-challenge", "token-1", "extra"]}
    check "other path is passed to the application" (other == (status404, "fallback"))

    deleteChallenge store token1
    after <- run app challengeRequest
    check "deleted token is passed to the application" (after == (status404, "fallback"))

stepsFillAndClearStore :: IO ()
stepsFillAndClearStore = do
    store <- newChallengeStore
    seen <- newIORef (0 :: Int)
    servedAtValidation <- newIORef Nothing
    let handler step = do
            modifyIORef' seen succ
            case step of
                Validation _ -> writeIORef servedAtValidation =<< lookupChallenge store token1
                _ -> pure ()
    handle <- http01Steps store handler

    handle validation1
    atValidation <- readIORef servedAtValidation
    check "token is served when the handler sees the validation" (atValidation == Just keyAuth1)

    handle (WaitingForValidation 0)
    during <- listChallenges store
    check "token is served while waiting" (during == [token1])

    handle (OtherError "stop")
    after <- listChallenges store
    check "token is removed after the last step" (null after)

    n <- readIORef seen
    check "wrapped handler sees every step" (n == 3)

stepsClearStoreWhenHandlerThrows :: IO ()
stepsClearStoreWhenHandlerThrows = do
    store <- newChallengeStore
    let handler step =
            case step of
                OtherError _ -> throwIO (ErrorCall "boom")
                _ -> pure ()
    handle <- http01Steps store handler
    handle validation1
    res <- try (handle (OtherError "stop"))
    check "exception of the wrapped handler is rethrown" (res == Left (ErrorCall "boom"))
    after <- listChallenges store
    check "token is removed when the last step throws" (null after)

-- | Runs an application, returns the status and the body of the response.
run :: Application -> Request -> IO (Status, LByteString.ByteString)
run app req = do
    out <- newIORef Nothing
    _ <- app req $ \rsp -> do
        body <- responseBody rsp
        writeIORef out (Just (responseStatus rsp, body))
        pure (error "no ResponseReceived in tests")
    maybe (fail "no response") pure =<< readIORef out

responseBody :: Response -> IO LByteString.ByteString
responseBody rsp = do
    let (_, _, withBody) = responseToStream rsp
    chunks <- newIORef mempty
    withBody $ \streamingBody ->
        streamingBody (\chunk -> modifyIORef' chunks (<> chunk)) (pure ())
    toLazyByteString <$> readIORef chunks

check :: String -> Bool -> IO ()
check name ok = do
    putStrLn $ (if ok then "pass: " else "FAIL: ") <> name
    unless ok exitFailure
