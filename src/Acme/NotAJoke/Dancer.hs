module Acme.NotAJoke.Dancer where

import Data.Maybe (fromJust)
import Control.Monad (void)
import Data.Text (Text)
import qualified Crypto.JOSE.JWK as JWK
import Control.Concurrent (threadDelay)

import Acme.NotAJoke.Account
import Acme.NotAJoke.Endpoint
import Acme.NotAJoke.Order
import Acme.NotAJoke.CSR
import Acme.NotAJoke.Certificate
import Acme.NotAJoke.Validation
import Acme.NotAJoke.Client

data AcmeDancer =
  AcmeDancer
  { baseUrl :: BaseUrl
  , accountJwk :: JWK.JWK
  , account :: Account "account-fetch"
  , csr :: CSR
  , order :: Order "order-create"
  , handleStep :: DanceStep -> IO ()
  }

data DanceStep
  = Validation ValidationProof
  | WaitingForValidation Int
  | OrderIsFinalized OrderFinalized
  | ValidOrder OrderInspected
  | InvalidOrder OrderInspected
  | OtherError Text
  | Done AcmeSingle Certificate
  | Prepare PrepareStep

basicDance :: FilePath -> DanceStep -> IO ()
basicDance certPath x =
  case x of
    Validation p -> do
      print ("proof is" :: Text, showProof p, "press enter to continue" :: Text)
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

runAcmeDance :: AcmeDancer -> IO ()
runAcmeDance dancer = do
    acme <- prepareAcmeOrder dancer.baseUrl dancer.accountJwk dancer.account dancer.csr dancer.order handleAcmeSingleStep
    go acme
  where
    go acme = do
      dancer.handleStep $ Validation (proof acme)
      _ <- acme.replyChallenge
      waitForValidOrder 0 acme

    handleAcmeSingleStep = dancer.handleStep . Prepare

    waitForValidOrder n acme = do
      dancer.handleStep (WaitingForValidation n)
      recentOrder <- fromJust <$> acme.pollOrder
      case Acme.NotAJoke.Order.status <$> readOrderInspected recentOrder of
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

showProof :: ValidationProof -> String
showProof (ValidationProof x1) = show x1
