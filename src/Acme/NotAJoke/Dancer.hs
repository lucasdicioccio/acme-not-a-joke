module Acme.NotAJoke.Dancer where

import Control.Concurrent (threadDelay)
import Control.Monad (void)
import qualified Crypto.JOSE.JWK as JWK
import Data.Text (Text)

import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Certificate
import Acme.NotAJoke.Api.Challenge (Token (..), isDNS01, isHTTP01, isTLSALPN01)
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
    = {- | the client is about to validate this authorization, the next
      'Validation' step carries its proof (useful to know which identifier
      the proof is for, e.g. with 'dns01RecordName', when the order has more
      than one identifier)
      -}
      Authorizing AcmeAuthorization
    | {- | the proof must be answerable (e.g. the DNS record set, the
      token served) before the step handler returns; there is one
      'Validation' per authorization to validate, and the server is told to
      check the challenges only after the last one, so all proofs must be
      answerable at the same time
      -}
      Validation (Token, KeyAuthorization, ValidationProof)
    | WaitingForValidation Int
    | OrderIsFinalized OrderFinalized
    | ValidOrder OrderInspected
    | InvalidOrder OrderInspected
    | OtherError Text
    | -- | an API call failed, the dance stops
      AcmeFailure AcmeError
    | Done AcmeSingle Certificate
    | Prepare PrepareStep

{- | Runs the dance with DNS-01 challenges: the 'ValidationProof' given in each
'Validation' step must be published as a TXT record at the
'dns01RecordName' of the identifier given in the preceding 'Authorizing' step
before the step handler returns.

DNS-01 challenges can validate wildcard identifiers: an order for
@*.example.com@ needs a TXT record at @_acme-challenge.example.com@. An order
for both @*.example.com@ and @example.com@ needs two TXT records at that same
name, so a step handler must add records rather than replace them.
-}
runAcmeDance_dns01 :: AcmeDancer -> IO ()
runAcmeDance_dns01 = runAcmeDance isDNS01

{- | Runs the dance with an HTTP-01 challenge: the 'KeyAuthorization' given in
the 'Validation' step must be served at
@http:\/\/{domain}\/.well-known\/acme-challenge\/{token}@ (on port 80) before the
step handler returns.

HTTP-01 challenges cannot validate wildcard identifiers, use
'runAcmeDance_dns01' for these.
-}
runAcmeDance_http01 :: AcmeDancer -> IO ()
runAcmeDance_http01 = runAcmeDance isHTTP01

{- | Runs the dance with a TLS-ALPN-01 challenge (RFC-8737): before the step
handler returns from the 'Validation' step, the TLS server on port 443 of the
domain must answer handshakes negotiating the @acme-tls/1@ protocol (ALPN)
for this server name with a self-signed certificate carrying the SHA-256
digest of the 'KeyAuthorization' (see
'Acme.NotAJoke.CertManagement.createTLSALPN01Certificate').

TLS-ALPN-01 challenges cannot validate wildcard identifiers, use
'runAcmeDance_dns01' for these.
-}
runAcmeDance_tlsalpn01 :: AcmeDancer -> IO ()
runAcmeDance_tlsalpn01 = runAcmeDance isTLSALPN01

runAcmeDance :: MatchChallenge -> AcmeDancer -> IO ()
runAcmeDance matchChallenge dancer = do
    prepared <-
        prepareAcmeOrder
            dancer.baseUrl
            dancer.accountJwk
            dancer.account
            dancer.csr
            dancer.order
            matchChallenge
            handleAcmeSingleStep
    either failed go prepared
  where
    go acme = do
        mapM_ announce acme.pendingAuthorizations
        replyAll acme acme.pendingAuthorizations

    announce authz = do
        dancer.handleStep $ Authorizing authz
        dancer.handleStep $ Validation authz.proof

    replyAll acme [] = waitForValidOrder 0 acme
    replyAll acme (authz : rest) = do
        replied <- authz.replyChallenge
        case replied of
            Left err -> failed err
            Right _ -> replyAll acme rest

    handleAcmeSingleStep = dancer.handleStep . Prepare

    failed = dancer.handleStep . AcmeFailure

    waitForValidOrder n acme = do
        dancer.handleStep (WaitingForValidation n)
        polled <- acme.pollOrder
        case polled of
            Left err -> failed err
            Right recentOrder ->
                case Acme.NotAJoke.Api.Order.status <$> readOrderInspected recentOrder of
                    Just OrderPending -> waitForValidOrder (succ n) acme
                    Just OrderProcessing -> waitForValidOrder (succ n) acme
                    Just OrderReady -> do
                        finalized <- acme.finalizeOrder
                        case finalized of
                            Left err -> failed err
                            Right x -> do
                                dancer.handleStep $ OrderIsFinalized x
                                waitForValidOrder (succ n) acme
                    Just OrderValid -> handleValid acme recentOrder
                    Just OrderInvalid -> dancer.handleStep $ InvalidOrder recentOrder
                    _ -> dancer.handleStep $ OtherError "could not inspect order"

    handleValid acme o = do
        dancer.handleStep $ ValidOrder o
        case readCertificateUrl o of
            Nothing -> dancer.handleStep $ OtherError "valid order without certificate url"
            Just certUrl -> do
                certif <- acme.fetchCertificate certUrl
                either failed (dancer.handleStep . Done acme) certif

{- | A dance for running from within GHCI (i.e., printing and expecting you to
press ENTER to continue).
-}
ghciDance :: FilePath -> DanceStep -> IO ()
ghciDance certPath x =
    case x of
        Authorizing authz -> do
            print ("authorizing" :: Text, authz.authIdentifier, ("wildcard" :: Text, authz.authWildcard))
            print ("TXT record (dns01) is" :: Text, dns01RecordName authz.authIdentifier)
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
        AcmeFailure err -> do
            print ("acme failure" :: Text, readProblem err, err)
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
