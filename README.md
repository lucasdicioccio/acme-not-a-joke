# ACME-not-a-joke

A library of primitives to perform ACME authentication certifications [RFC-8555](https://datatracker.ietf.org/doc/html/rfc8555).

## status of this library

Incomplete and subject to changes. But the happy path will work.

What I'd like to change with low appetite:
- support more features (e.g., key changes and account deactivation)

Errors are returned as values: API calls return an `Either AcmeError a`, where
an `AcmeError` tells whether the request could not be signed, whether the
server rejected the request (in which case `readProblem` gives the
[RFC-7807](https://datatracker.ietf.org/doc/html/rfc7807) problem document sent
by the ACME server), or whether the response was not the expected one. Only
network-level failures (no connection, TLS errors) are raised as exceptions (the
`HttpException` from `http-client`).

Design-wise, the library uses a TypeFamily pattern to specify/modulate which
fields are available for ACME resources in various APIs/states (e.g., an
`Account` in the `"account-create"` message has no "orders" fields).

## what about the name of the library

We use ACME-not-a-joke as a package name because `acme-` packages on Hackage
typically are "joke" packages.

## example

```console
bash scripts/gen-csr.sh staging example dicioccio.fr
```

create a new account

```hs
import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.Api.Endpoint
import Acme.NotAJoke.Api.Nonce
import Acme.NotAJoke.KeyManagement
import Acme.NotAJoke.LetsEncrypt
import Data.Maybe

loadedjwk <- loadJWKFile "staging/key.jwk"
let jwk = fromJust loadedjwk
let contacts = ["mailto:certmaster@dicioccio.fr"]

Right leDir <- fetchDirectory (directory staging_letsencryptv2)
Right nonce0 <- getNonce leDir.newNonce
created <- postCreateAccount jwk leDir.newAccount nonce0 (createAccount contacts)
```

inspect what the server complained about, if anything

```hs
either (\err -> print (readProblem err)) print created
```

create a new cert

```hs
import Acme.NotAJoke.CertManagement
import Acme.NotAJoke.Client
import Acme.NotAJoke.Dancer
import Acme.NotAJoke.KeyManagement
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.Api.CSR
import Acme.NotAJoke.Api.Order
import Acme.NotAJoke.LetsEncrypt
import Data.Maybe

jwk <- fromJust <$> loadJWKFile "staging/key.jwk"
der <- loadDER "staging-example/certificate.csr.der"

let o = createOrder (Nothing, Nothing) [ OrderIdentifier DNSOrder "example.dicioccio.fr" ]
runAcmeDance_dns01 (AcmeDancer staging_letsencryptv2 jwk (fetchAccount ["mailto:certmaster@dicioccio.fr"]) (CSR der) o (ghciDance "staging-example/certificate.pem"))
```

### wildcard certificates with dns-01

A wildcard such as `*.example.com` is an identifier of the order like any other
(RFC-8555 sections 7.1.3 and 7.1.4), and it must be validated with a DNS-01
challenge. The server gives an authorization for `example.com` (without the
`*.`, with `wildcard: true`), so the TXT record holding the proof goes at
`_acme-challenge.example.com`: `dns01RecordName` (in `Acme.NotAJoke.Client`)
gives that name.

An order can mix a wildcard with its apex. There is one authorization per
identifier, so the dance emits one `Authorizing` step (which identifier, whether
it is the wildcard) followed by one `Validation` step (the proof) per
authorization, and tells the server to check the challenges only after the last
one. For `*.example.com` and `example.com` that means two TXT records at the
same name, which must be present at the same time: add records, do not replace
them. Authorizations the server already considers valid (e.g. reused from an
earlier order) are skipped.

```hs
import Acme.NotAJoke.Api.Validation (ValidationProof (..))
import Data.IORef
import Data.List.NonEmpty (NonEmpty (..))

Right key <- loadOrCreateRSAKeyPEM "staging-wildcard/key.pem"
Right csr <- createCSR key ("example.dicioccio.fr" :| ["*.example.dicioccio.fr"])

let o = createOrder (Nothing, Nothing) [ OrderIdentifier DNSOrder "example.dicioccio.fr", OrderIdentifier DNSOrder "*.example.dicioccio.fr" ]
current <- newIORef Nothing
let handle step = case step of
      Authorizing authz -> writeIORef current (Just (dns01RecordName (authIdentifier authz)))
      Validation (_, _, ValidationProof txt) -> do
        Just name <- readIORef current
        addTxtRecord name txt -- your DNS provider, then wait for propagation
      WaitingForValidation n -> threadDelay (n * 1000000)
      Done _ cert -> storeCert "staging-wildcard/certificate.pem" cert
      _ -> pure ()
runAcmeDance_dns01 (AcmeDancer staging_letsencryptv2 jwk (fetchAccount ["mailto:certmaster@dicioccio.fr"]) csr o handle)
```

### http-01 challenges with wai

The example above uses a DNS-01 challenge. The `acme-not-a-joke-wai` package
(in the `acme-not-a-joke-wai` directory) serves HTTP-01 challenges from a
wai application: a middleware answers the
`GET /.well-known/acme-challenge/{token}` requests of the ACME server, and the
dance fills and clears the store of challenges read by the middleware.

```hs
import Acme.NotAJoke.Wai.Http01
import Control.Concurrent (forkIO, threadDelay)
import Network.Wai.Handler.Warp (run)

store <- newChallengeStore
-- the ACME server connects on port 80
_ <- forkIO $ run 80 (http01Middleware store myApplication)

let handle step = case step of
      WaitingForValidation n -> threadDelay (n * 1000000)
      Done _ cert -> storeCert "staging-example/certificate.pem" cert
      _ -> pure ()
runAcmeDance_http01_wai store (AcmeDancer staging_letsencryptv2 jwk (fetchAccount ["mailto:certmaster@dicioccio.fr"]) (CSR der) o handle)
```

HTTP-01 challenges cannot validate wildcard identifiers, which require a DNS-01
challenge.

The same package answers TLS-ALPN-01 challenges (RFC-8737) from the HTTPS
server itself, without port 80: `runAcmeDance_tlsalpn01_wai` with a
`TlsAlpn01Store`, and `withTlsAlpn01` on the warp-tls settings (see
`Acme.NotAJoke.Wai.TlsAlpn01`).

Your program starts the dance (nothing runs in the background) and the only
incoming request is the one the ACME server sends to port 80. The library
writes no file on its own: keys, CSR and certificate go where the functions you
call put them (above, only `storeCert` writes something). See
[acme-not-a-joke-wai/README.md](acme-not-a-joke-wai/README.md) for who
initiates what, which files are involved, and a complete example.

The same package has `Acme.NotAJoke.Wai.WarpTLS`: a certificate store read by
a warp-tls server at each TLS handshake, so that the certificate you just
obtained (or renewed) is served without restarting.

```hs
import Acme.NotAJoke.Wai.WarpTLS
import Network.Wai.Handler.Warp (defaultSettings, setPort)
import Network.Wai.Handler.WarpTLS (runTLS)

certificates <- newCertificateStore
_ <- forkIO $ runTLS (liveTlsSettings certificates) (setPort 443 defaultSettings) myApplication

-- in the step handler, with the key that signed the CSR
--   Done _ cert -> installCertificate certificates key cert
```

### automatic HTTPS with warp

The `acme-not-a-joke-warp` package (in the `acme-not-a-joke-warp` directory)
puts the above together, in the spirit of Caddy: it runs your wai application
over HTTPS, gets the certificates with HTTP-01 challenges (or TLS-ALPN-01
challenges, without port 80) when the program
starts, stores them on disk, renews them before they expire and serves the new
ones without restarting.

```hs
import Acme.NotAJoke.LetsEncrypt (letsencryptv2)
import Acme.NotAJoke.Warp
import Data.List.NonEmpty (NonEmpty (..))

main :: IO ()
main =
  runAutoHttps
    (defaultAutoHttps letsencryptv2 ("example.dicioccio.fr" :| []) ["mailto:certmaster@dicioccio.fr"] "state")
    myApplication
```

See [acme-not-a-joke-warp/README.md](acme-not-a-joke-warp/README.md) for what
runs, what is stored, and when certificates are renewed.

### changing the account key

`Acme.NotAJoke.Api.KeyChange` builds account key rollovers (RFC-8555 section
7.3.5): an inner JWS signed with the new key, wrapped in a request signed with
the old key. `changeAccountKey` (in `Acme.NotAJoke.Client`) fetches the
directory, nonce and account and sends it. Once it succeeds, the old key no
longer works for the account: write the new key down before calling it.

```hs
import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Client
import Acme.NotAJoke.KeyManagement
import Acme.NotAJoke.LetsEncrypt

Just oldJwk <- loadJWKFile "staging/key.jwk"
newJwk <- genJWKrsa4096
writeJWKFile newJwk "staging/key.new.jwk"

changeAccountKey staging_letsencryptv2 oldJwk newJwk (fetchAccount ["mailto:certmaster@dicioccio.fr"])
```

### keys and CSRs without openssl

The `scripts/gen-csr.sh` script above calls `openssl` to generate the key of
the certificate and the CSR. You can stay in Haskell instead:
`Acme.NotAJoke.KeyManagement` and `Acme.NotAJoke.CertManagement` have helpers
to create, load and write account keys (JWK), RSA keys (PEM, DER), CSRs (PEM,
DER) and certificate chains (PEM).

```hs
import Acme.NotAJoke.CertManagement
import Acme.NotAJoke.KeyManagement
import Data.List.NonEmpty (NonEmpty (..))

-- the account key, created on the first run (directories must exist)
Right jwk <- loadOrCreateJWKFile "staging/key.jwk"

-- the key of the certificate (which must differ from the account key)
Right key <- loadOrCreateRSAKeyPEM "staging-example/key.pem"

-- a CSR for the names of the order, to pass to the AcmeDancer
Right csr <- createCSR key ("example.dicioccio.fr" :| [])

-- optionally, keep a copy that `openssl req -in ... -text` can read
writeCSRPEM csr "staging-example/certificate.csr"

-- once the dance is over, inspect what the server returned
Right chain <- loadCertificateChain "staging-example/certificate.pem"
```

Existing files made with `openssl` load as well: see `loadRSAKeyPEM` and
`loadCSR`.

### account keys and JWS algorithms

The account key need not be an RSA key: requests are signed with the JWS
algorithm that fits the key (see `acmeJWSAlg` in `Acme.NotAJoke.Api.JWS`),
`RS256` for RSA keys, `ES256`/`ES384`/`ES512` for EC keys on the P-256/P-384/P-521
curves and `EdDSA` for Ed25519 keys. Let's Encrypt accepts `RS256`, `ES256`
and `ES384`. To use another algorithm the server accepts (e.g. `PS256` with
an RSA key), pin it in the key with `setAcmeJWSAlg`: it is stored in the JWK
file.

```hs
import Acme.NotAJoke.KeyManagement

-- a smaller and faster account key, signing with ES256
jwk <- genJWKecP256
writeJWKFile jwk "staging/key.jwk"
```

The key of the certificate is unaffected (it is an RSA key, see above).

### revoking a certificate

`Acme.NotAJoke.Api.Revocation` builds revocation requests (RFC-8555 section
7.6) with an optional reason, and `Acme.NotAJoke.Client` sends them. Sign with
the account key, or with the key of the certificate when the account key is
lost (no account is needed then).

```hs
import Acme.NotAJoke.Api.Revocation
import Acme.NotAJoke.CertManagement
import Acme.NotAJoke.Client
import Acme.NotAJoke.KeyManagement

Right (cert : _) <- loadCertificateChain "staging-example/certificate.pem"
let rev = revocation (Just Superseded) cert

-- with the account key
revokeCertificate staging_letsencryptv2 jwk (fetchAccount ["mailto:certmaster@dicioccio.fr"]) rev

-- or with the key of the certificate
Right key <- loadRSAKeyPEM "staging-example/key.pem"
revokeCertificateWithCertKey staging_letsencryptv2 (jwkFromRSAKey key) rev
```

### deactivating an account

`deactivateAccount` (in `Acme.NotAJoke.Client`) fetches the directory, nonce
and account, then deactivates the account (RFC-8555 section 7.3.6). This
cannot be undone: the server rejects every later request signed with the key
of the account. `postDeactivateAccount` (in `Acme.NotAJoke.Api.Account`) is
the single API call, for when you already know the KID of the account.

```hs
import Acme.NotAJoke.Api.Account
import Acme.NotAJoke.Client
import Acme.NotAJoke.KeyManagement
import Acme.NotAJoke.LetsEncrypt

Just jwk <- loadJWKFile "staging/key.jwk"

deactivateAccount staging_letsencryptv2 jwk (fetchAccount ["mailto:certmaster@dicioccio.fr"])
```

## website

The site at https://lucasdicioccio.github.io/acme-not-a-joke/ is a
[Kitchen-Sink](https://kitchensink-tech.github.io/) site. Its sources are in
`website/src/` and the published output is in `docs/`, see
[website/README.md](website/README.md).

## todo list

- some more doc
