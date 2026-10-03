# ACME-not-a-joke

A library of primitives to perform ACME authentication certifications [RFC-8555](https://datatracker.ietf.org/doc/html/rfc8555).

## status of this library

Incomplete and subject to changes. But the happy path will work.

What I'd like to change with low appetite:
- support more features (especially, revocations)
- allow to tweak algos (works for RS256 only)

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

## website

The site at https://lucasdicioccio.github.io/acme-not-a-joke/ is a
[Kitchen-Sink](https://kitchensink-tech.github.io/) site. Its sources are in
`website/src/` and the published output is in `docs/`, see
[website/README.md](website/README.md).

## todo list

- tweak supported algos
- some more doc
- keyChange
- deactivate account
