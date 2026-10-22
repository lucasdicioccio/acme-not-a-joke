{- | Answers TLS-ALPN-01 challenges (RFC-8737) from a running warp-tls server.

The ACME server validates a TLS-ALPN-01 challenge by opening a TLS connection
to port 443 of the domain, asking for the domain (SNI) and for the
@acme-tls/1@ protocol only (ALPN). It expects a self-signed certificate for
the domain carrying the SHA-256 digest of the key authorization in a critical
@acmeIdentifier@ extension, and closes the connection after the handshake.
Hence no port 80 is needed: the HTTPS server answers the challenges itself.

This module provides a 'TlsAlpn01Store' shared between two parties:

* the HTTPS server, whose TLS settings are wrapped with 'withTlsAlpn01'. It
  presents the challenge certificate of the store to the handshakes asking for
  @acme-tls/1@, and behaves as before for every other handshake (e.g., with
  the certificates of a "Acme.NotAJoke.Wai.WarpTLS" store)
* a dance ('runAcmeDance_tlsalpn01_wai') or a step handler ('tlsAlpn01Steps')
  adding the challenge certificate before the ACME server is told to validate
  the challenge and removing it once the dance is over

TLS-ALPN-01 challenges cannot validate wildcard identifiers.

= Limits

The @tls@ library lets the server choose its certificate from the server name
only, before or after it chooses the protocol depending on the TLS version.
'withTlsAlpn01' relies on the order of TLS 1.3, where the protocol is chosen
first: the TLS 1.3 support of the server (the default of warp-tls) must be
left enabled. ACME servers (e.g. Let's Encrypt) use TLS 1.3 when the server
supports it. A client asking for @acme-tls/1@ over TLS 1.2 gets the regular
certificate, which fails the validation.

= Where things are stored

This module writes no file. The 'TlsAlpn01Store' is in memory and only holds
the challenge certificates for the time of a dance. The key of a challenge
certificate is generated for the dance and thrown away afterwards.
-}
module Acme.NotAJoke.Wai.TlsAlpn01 (
    -- * store
    TlsAlpn01Store,
    newTlsAlpn01Store,
    insertTlsAlpn01,
    deleteTlsAlpn01,
    lookupTlsAlpn01,
    listTlsAlpn01,

    -- * warp-tls
    withTlsAlpn01,
    tlsAlpn01Hooks,

    -- * certificates
    challengeCredential,

    -- * dance
    runAcmeDance_tlsalpn01_wai,
    tlsAlpn01Steps,
) where

import Control.Concurrent (ThreadId, myThreadId)
import Control.Exception (finally, throwIO)
import qualified Crypto.PubKey.RSA as RSA
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import qualified Data.Text as Text
import Data.Time.Clock (addUTCTime, getCurrentTime)
import qualified Data.X509 as X509
import GHC.Clock (getMonotonicTime)
import Network.TLS (Credential, Credentials (..), HostName)
import qualified Network.TLS as TLS
import Network.Wai.Handler.WarpTLS (TLSSettings, tlsServerHooks)

import qualified Acme.NotAJoke.Api.Authorization as Authorization
import Acme.NotAJoke.Api.Validation (KeyAuthorization (..))
import Acme.NotAJoke.CertManagement (acmeTLSALPNProtocol, createTLSALPN01Certificate)
import Acme.NotAJoke.Client (PrepareStep (..))
import Acme.NotAJoke.Dancer (AcmeDancer (..), DanceStep (..), runAcmeDance_tlsalpn01)
import Acme.NotAJoke.KeyManagement (genRSAKey)

{- | The challenge certificates being served: one credential per server name.

A same store can be shared by concurrent dances (for different names).
-}
data TlsAlpn01Store = TlsAlpn01Store
    { challenges :: IORef (Map HostName Credential)
    , negotiating :: IORef (Map ThreadId Double)
    {- ^ the handshakes which chose @acme-tls/1@ and still have to choose their
    certificate, by thread, with the (monotonic) time they chose the protocol
    -}
    }

-- | Creates an empty store.
newTlsAlpn01Store :: IO TlsAlpn01Store
newTlsAlpn01Store = TlsAlpn01Store <$> newIORef Map.empty <*> newIORef Map.empty

{- | Starts presenting a challenge certificate (see 'challengeCredential') to
the clients asking for @acme-tls/1@ and for a server name.

Names are compared without regard to case.
-}
insertTlsAlpn01 :: TlsAlpn01Store -> HostName -> Credential -> IO ()
insertTlsAlpn01 store name cred =
    atomicModifyIORef' store.challenges (\m -> (Map.insert (normalize name) cred m, ()))

-- | Stops presenting the challenge certificate of a server name.
deleteTlsAlpn01 :: TlsAlpn01Store -> HostName -> IO ()
deleteTlsAlpn01 store name =
    atomicModifyIORef' store.challenges (\m -> (Map.delete (normalize name) m, ()))

-- | The challenge certificate of a server name.
lookupTlsAlpn01 :: TlsAlpn01Store -> HostName -> IO (Maybe Credential)
lookupTlsAlpn01 store name =
    Map.lookup (normalize name) <$> readIORef store.challenges

-- | The server names which currently have a challenge certificate.
listTlsAlpn01 :: TlsAlpn01Store -> IO [HostName]
listTlsAlpn01 store = Map.keys <$> readIORef store.challenges

normalize :: HostName -> HostName
normalize = map toLower

{- | Makes warp-tls settings answer the TLS-ALPN-01 challenges of the store,
see 'tlsAlpn01Hooks'.

Apply it last, on settings which already read their certificates (e.g.,
'Acme.NotAJoke.Wai.WarpTLS.liveTlsSettings'):

> runTLS (withTlsAlpn01 challenges (liveTlsSettings certificates)) settings application
-}
withTlsAlpn01 :: TlsAlpn01Store -> TLSSettings -> TLSSettings
withTlsAlpn01 store settings =
    settings{tlsServerHooks = tlsAlpn01Hooks store (tlsServerHooks settings)}

{- | Wraps the server hooks of a TLS server to answer the TLS-ALPN-01
challenges of the store.

* the protocol hook ('TLS.onALPNClientSuggest') chooses @acme-tls/1@ when
  the client asks for it. Otherwise it calls the hook it wraps or, when there
  is none, does what warp-tls does: choose @h2@ when the client asks for it,
  @http/1.1@ otherwise. Hence, when HTTP/2 is disabled in the warp settings,
  set a hook choosing @http/1.1@ before wrapping;
* the server name hook ('TLS.onServerNameIndication') presents the challenge
  certificate of the server name to a handshake which chose @acme-tls/1@, and
  nothing when there is none (the handshake fails). Other handshakes go to
  the hook it wraps.

See the limits in the description of the module: TLS 1.3 only.
-}
tlsAlpn01Hooks :: TlsAlpn01Store -> TLS.ServerHooks -> TLS.ServerHooks
tlsAlpn01Hooks store hooks =
    hooks
        { TLS.onALPNClientSuggest = Just chooseProtocol
        , TLS.onServerNameIndication = chooseCredentials
        }
  where
    otherProtocols :: [ByteString] -> IO ByteString
    otherProtocols = fromMaybe warpProtocols (TLS.onALPNClientSuggest hooks)

    chooseProtocol :: [ByteString] -> IO ByteString
    chooseProtocol protocols
        | acmeTLSALPNProtocol `elem` protocols = do
            tid <- myThreadId
            now <- getMonotonicTime
            -- with TLS 1.2, the server name hook runs before this one and
            -- never removes the entry: drop the old ones
            atomicModifyIORef' store.negotiating $ \m ->
                (Map.insert tid now (Map.filter (> now - 60) m), ())
            pure acmeTLSALPNProtocol
        | otherwise = otherProtocols protocols

    chooseCredentials :: Maybe HostName -> IO Credentials
    chooseCredentials name = do
        tid <- myThreadId
        acme <- atomicModifyIORef' store.negotiating (\m -> (Map.delete tid m, Map.member tid m))
        if acme
            then Credentials . maybe [] pure <$> maybe (pure Nothing) (lookupTlsAlpn01 store) name
            else TLS.onServerNameIndication hooks name

-- | The protocols warp-tls chooses when HTTP/2 is enabled.
warpProtocols :: [ByteString] -> IO ByteString
warpProtocols protocols
    | "h2" `elem` protocols = pure "h2"
    | otherwise = pure "http/1.1"

{- | Creates the challenge certificate for a server name and the key
authorization of a TLS-ALPN-01 challenge, signed with a key (see
'Acme.NotAJoke.CertManagement.createTLSALPN01Certificate'). It is valid from
a day before now to a week after now.

The key can be any RSA key except the account key, e.g. a throw-away one from
'Acme.NotAJoke.KeyManagement.genRSAKey'.
-}
challengeCredential :: RSA.PrivateKey -> HostName -> KeyAuthorization -> IO (Either String Credential)
challengeCredential key name keyAuth = do
    now <- getCurrentTime
    created <- createTLSALPN01Certificate key (addUTCTime (-86400) now, addUTCTime (7 * 86400) now) (Text.pack name) keyAuth
    pure $ fmap (\cert -> (X509.CertificateChain [cert], X509.PrivKeyRSA key)) created

{- | Runs the dance with a TLS-ALPN-01 challenge served from the store.

The challenge certificate (for the identifier of the authorization, with a new
RSA-2048 key) is added to the store before the 'handleStep' of the dancer sees
the 'Validation' step, and is removed when the dance is over (whether the
dance succeeds, fails, or throws an exception).

Throws an 'IOError' when the challenge certificate cannot be created (e.g., the
authorization of the ACME server has no identifier).

The 'handleStep' of the dancer still is responsible for the other steps (e.g.,
waiting between two polls and storing the certificate).
-}
runAcmeDance_tlsalpn01_wai :: TlsAlpn01Store -> AcmeDancer -> IO ()
runAcmeDance_tlsalpn01_wai store dancer = do
    st <- newStepState
    runAcmeDance_tlsalpn01 (dancer{handleStep = serveSteps store st dancer.handleStep})
        `finally` stopServing store st

{- | Wraps a step handler to serve TLS-ALPN-01 challenges from the store, for
use with 'runAcmeDance_tlsalpn01' or with a custom matcher.

The challenge certificate is added to the store before the wrapped handler sees
the 'Validation' step, and is removed after the wrapped handler has seen the
last step of the dance ('Done', 'InvalidOrder', 'OtherError' or
'AcmeFailure'). The server name comes from the authorization, in the
'GotAuthorization' step.

The certificate is not removed if the dance throws an exception, see
'runAcmeDance_tlsalpn01_wai' for a variant handling exceptions.
-}
tlsAlpn01Steps :: TlsAlpn01Store -> (DanceStep -> IO ()) -> IO (DanceStep -> IO ())
tlsAlpn01Steps store handler = do
    st <- newStepState
    pure (serveSteps store st handler)

data StepState = StepState
    { identifier :: IORef (Maybe HostName)
    -- ^ the name of the authorization
    , served :: IORef [HostName]
    -- ^ the names added to the store
    }

newStepState :: IO StepState
newStepState = StepState <$> newIORef Nothing <*> newIORef []

-- | Step handler keeping track of the names it added to the store.
serveSteps :: TlsAlpn01Store -> StepState -> (DanceStep -> IO ()) -> DanceStep -> IO ()
serveSteps store st handler step =
    case step of
        Prepare (GotAuthorization authz) -> do
            let name = Text.unpack . Authorization.value . Authorization.identifier <$> Authorization.readAuthorization authz
            writeIORef st.identifier name
            handler step
        Validation (_, keyAuth, _) -> do
            known <- readIORef st.identifier
            name <- maybe (throwIO (userError "tls-alpn-01: no identifier in the authorization")) pure known
            key <- genRSAKey 2048
            created <- challengeCredential key name keyAuth
            cred <- either (throwIO . userError . ("tls-alpn-01: " <>)) pure created
            atomicModifyIORef' st.served (\names -> (name : names, ()))
            insertTlsAlpn01 store name cred
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
    final = handler step `finally` stopServing store st

-- | Removes the names added by a step handler.
stopServing :: TlsAlpn01Store -> StepState -> IO ()
stopServing store st = do
    names <- atomicModifyIORef' st.served (\names -> ([], names))
    mapM_ (deleteTlsAlpn01 store) names
