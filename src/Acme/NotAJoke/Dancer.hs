module Acme.NotAJoke.Dancer where

import Control.Concurrent (threadDelay)
import Control.Monad (void)
import qualified Crypto.JOSE.JWK as JWK
import Data.Maybe (fromJust)
import Data.Text (Text)

import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Certificate
import Acme.NotAJoke.Api.Challenge (Token (..), isDNS01)
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Order
import Acme.NotAJoke.Api.Validation
import Acme.NotAJoke.Client

data AcmeDancer
    = AcmeDancer
    { baseUrl :: BaseUrl
    , accountJwk :: JWK.JWK
    , account :: Account "account-fetch"
    , csr :: CSR
    , order :: Order "order-create"
    , handleStep :: DanceStep -> IO ()
    }

data DanceStep
    = Validation (Token, KeyAuthorization, ValidationProof)
    | WaitingForValidation Int
    | OrderIsFinalized OrderFinalized
    | ValidOrder OrderInspected
    | InvalidOrder OrderInspected
    | OtherError Text
    | Done AcmeSingle Certificate
    | Prepare PrepareStep

runAcmeDance_dns01 :: AcmeDancer -> IO ()
runAcmeDance_dns01 = runAcmeDance isDNS01

runAcmeDance :: MatchChallenge -> AcmeDancer -> IO ()
runAcmeDance matchChallenge dancer = do
    acme <-
        prepareAcmeOrder
            dancer.baseUrl
            dancer.accountJwk
            dancer.account
            dancer.csr
            dancer.order
            matchChallenge
            handleAcmeSingleStep
    go acme
  where
    go acme = do
        dancer.handleStep $ Validation acme.proof
        _ <- acme.replyChallenge
        waitForValidOrder 0 acme

    handleAcmeSingleStep = dancer.handleStep . Prepare

    waitForValidOrder n acme = do
        dancer.handleStep (WaitingForValidation n)
        recentOrder <- fromJust <$> acme.pollOrder
        case Acme.NotAJoke.Api.Order.status <$> readOrderInspected recentOrder of
            Just OrderPending -> waitForValidOrder (succ n) acme
            Just OrderProcessing -> waitForValidOrder (succ n) acme
            Just OrderReady -> do
                x <- fromJust <$> acme.finalizeOrder
                dancer.handleStep $ OrderIsFinalized x
                waitForValidOrder (succ n) acme
            Just OrderValid -> handleValid acme recentOrder
            Just OrderInvalid -> dancer.handleStep $ InvalidOrder recentOrder
            _ -> dancer.handleStep $ OtherError "could not inspect order"

    handleValid acme o = do
        dancer.handleStep $ ValidOrder o
        let certUrl = certificate =<< (readOrderInspected o)
        certif <- acme.fetchCertificate (fromJust certUrl)
        dancer.handleStep $ Done acme (fromJust certif)

{- | A dance for running from within GHCI (i.e., printing and expecting you to
press ENTER to continue).
-}
ghciDance :: FilePath -> DanceStep -> IO ()
ghciDance certPath x =
    case x of
        Validation (tok, keyAuth, sha) -> do
            print ("token (http01) is" :: Text, showToken tok)
            print ("key authorization (http01) is" :: Text, showKeyAuth keyAuth)
            print ("sha256 (dns01) is" :: Text, showProof sha)
            print ("press enter to continue" :: Text)
            void getLine
        OrderIsFinalized o -> do
            print ("finalized" :: Text, o)
        ValidOrder o -> do
            print ("order valid" :: Text, o)
        WaitingForValidation n -> do
            print ("waiting" :: Text, n)
            threadDelay $ n * 1000000
        Done _ cert -> do
            storeCert certPath cert
            print cert
        InvalidOrder o -> do
            print ("order invalid" :: Text, o)
        OtherError txt -> do
            print ("order invalid" :: Text, txt)
        Prepare Starting -> do
            print ("starting" :: Text)
        Prepare GettingNonce -> do
            print ("getting-nonce" :: Text)
        Prepare (GotDirectory d) -> do
            print ("listed directory" :: Text, d)
        Prepare (GotAccount a) -> do
            print ("got account" :: Text, a)
        Prepare (GotOrder o) -> do
            print ("got order" :: Text, o)
        Prepare (GotAuthorization a) -> do
            print ("got authorization" :: Text, a)

showToken :: Token -> Text
showToken (Token x1) = x1

showKeyAuth :: KeyAuthorization -> Text
showKeyAuth (KeyAuthorization x1) = x1

showProof :: ValidationProof -> Text
showProof (ValidationProof x1) = x1
