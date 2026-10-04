{- | Hands certificates to a running warp-tls server.

A warp-tls server started with 'Network.Wai.Handler.WarpTLS.tlsSettings' reads
its certificate once, when it starts. This module provides a
'CertificateStore' shared between two parties:

* the HTTPS server, started with 'liveTlsSettings', which reads the store at
  every TLS handshake
* whatever obtains certificates (e.g., the 'Acme.NotAJoke.Dancer.Done' step of an ACME dance, see
  'installCertificate'), which writes into the store

Hence a certificate that is obtained or renewed while the server runs is
presented to the next connection, without a restart. Connections that already
are established are left alone.

The store is in memory only: writing the certificate to a file (and loading it
back with 'loadCredential' when the program starts) is up to the application.

Until the store has a credential for a connection, TLS handshakes fail (the
server has no certificate to present); plain HTTP is not affected.
-}
module Acme.NotAJoke.Wai.WarpTLS (
    -- * store
    CertificateStore,
    newCertificateStore,
    setCredential,
    setCredentialFor,
    deleteCredentialFor,
    clearCredentials,
    lookupCredential,

    -- * warp-tls
    liveTlsSettings,
    sniCredentials,

    -- * credentials
    credentialFromCertificate,
    credentialFromPEM,
    loadCredential,

    -- * dance
    installCertificate,
) where

import qualified Crypto.PubKey.RSA as RSA
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.IORef (IORef, atomicModifyIORef', atomicWriteIORef, newIORef, readIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.X509 as X509
import Network.TLS (Credential, Credentials (..), HostName)
import qualified Network.TLS as TLS
import Network.Wai.Handler.WarpTLS (TLSSettings, tlsSettingsSni)

import Acme.NotAJoke.Api.Certificate (Certificate, readPEM)
import Acme.NotAJoke.CertManagement (certificateChain)

data Stored = Stored
    { fallback :: Maybe Credential
    , byName :: Map HostName Credential
    }

{- | The credentials (certificate chain and private key) a TLS server
presents.

A store has at most one default credential and at most one credential per
server name.
-}
newtype CertificateStore = CertificateStore (IORef Stored)

-- | Creates an empty store.
newCertificateStore :: IO CertificateStore
newCertificateStore = CertificateStore <$> newIORef (Stored Nothing Map.empty)

{- | Sets the default credential: the one presented when there is no
credential for the server name asked by the client (or when the client asks
for no name).

This is all you need when the server has a single certificate.
-}
setCredential :: CertificateStore -> Credential -> IO ()
setCredential (CertificateStore ref) cred =
    atomicModifyIORef' ref (\s -> (s{fallback = Just cred}, ()))

{- | Sets the credential presented to clients asking for a given server name
(the SNI extension of TLS).

Names are compared without regard to case and must match exactly: there is no
wildcard matching (use 'setCredential' for a wildcard certificate).
-}
setCredentialFor :: CertificateStore -> HostName -> Credential -> IO ()
setCredentialFor (CertificateStore ref) name cred =
    atomicModifyIORef' ref (\s -> (s{byName = Map.insert (normalize name) cred s.byName}, ()))

-- | Removes the credential of a server name.
deleteCredentialFor :: CertificateStore -> HostName -> IO ()
deleteCredentialFor (CertificateStore ref) name =
    atomicModifyIORef' ref (\s -> (s{byName = Map.delete (normalize name) s.byName}, ()))

-- | Removes every credential, including the default one.
clearCredentials :: CertificateStore -> IO ()
clearCredentials (CertificateStore ref) =
    atomicWriteIORef ref (Stored Nothing Map.empty)

{- | The credential presented for a server name: the one set for this name if
any, the default one otherwise.
-}
lookupCredential :: CertificateStore -> Maybe HostName -> IO (Maybe Credential)
lookupCredential (CertificateStore ref) name = do
    s <- readIORef ref
    pure $ case (`Map.lookup` s.byName) . normalize =<< name of
        Just cred -> Just cred
        Nothing -> s.fallback

normalize :: HostName -> HostName
normalize = map toLower

{- | Settings for 'Network.Wai.Handler.WarpTLS.runTLS' which read the
credential in the store at every TLS handshake.

These are the default settings of warp-tls with a hook on the server name
indication: update the record to change other settings, but leave
'Network.Wai.Handler.WarpTLS.tlsCredentials' and the
'TLS.onServerNameIndication' hook alone (or call 'sniCredentials' from your own
hook).
-}
liveTlsSettings :: CertificateStore -> TLSSettings
liveTlsSettings = tlsSettingsSni . sniCredentials

{- | The 'TLS.onServerNameIndication' hook reading the store, for use with
'tlsSettingsSni' or with a TLS server which is not warp-tls.
-}
sniCredentials :: CertificateStore -> Maybe HostName -> IO Credentials
sniCredentials store name =
    Credentials . maybe [] pure <$> lookupCredential store name

{- | Builds a credential from the certificate returned by the ACME server (the
one given in the 'Acme.NotAJoke.Dancer.Done' step) and the private key that
signed the CSR.
-}
credentialFromCertificate :: RSA.PrivateKey -> Certificate -> Either String Credential
credentialFromCertificate key cert = do
    chain <- certificateChain (readPEM cert)
    case chain of
        [] -> Left "no certificate in the response of the ACME server"
        _ -> Right (X509.CertificateChain chain, X509.PrivKeyRSA key)

{- | Builds a credential from the content of PEM files: the certificate chain
(leaf certificate first) then the private key.
-}
credentialFromPEM :: ByteString -> ByteString -> Either String Credential
credentialFromPEM = TLS.credentialLoadX509FromMemory

{- | Loads a credential from PEM files: the certificate chain (leaf
certificate first, as written by 'Acme.NotAJoke.Api.Certificate.storeCert')
then the private key (as written by
'Acme.NotAJoke.KeyManagement.writeRSAKeyPEM').

Typically called when the program starts, to serve the certificate obtained
by a previous run.
-}
loadCredential :: FilePath -> FilePath -> IO (Either String Credential)
loadCredential = TLS.credentialLoadX509

{- | Makes a certificate returned by the ACME server the default credential
of the store, see 'credentialFromCertificate' and 'setCredential'.

The store is left unchanged when the certificate cannot be parsed.
-}
installCertificate :: CertificateStore -> RSA.PrivateKey -> Certificate -> IO (Either String ())
installCertificate store key cert =
    traverse (setCredential store) (credentialFromCertificate key cert)
