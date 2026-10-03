# ACME-not-a-joke

A library of primitives to perform ACME authentication certifications [RFC-8555](https://datatracker.ietf.org/doc/html/rfc8555).

## status of this library

Incomplete and subject to changes. But the happy path will work.

What I'd like to change with low appetite:
- support more features (especially, revocations)
- allow to tweak algos (works for RS256 only)

What I'd like to change with low appetite:
- no longer use `wreq` (it returns non-200 with exception)

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
import Acme.NotAJoke.Client
import Acme.NotAJoke.Api.Directory
import Acme.NotAJoke.KeyManagement
import Acme.NotAJoke.LetsEncrypt
import Data.Maybe

loadedjwk <- loadJWKFile "staging/key.jwk"
let jwk = fromJust loadedjwk
let contacts = ["mailto:certmaster@dicioccio.fr"]

leDir <- fetchDirectory (directory staging_letsencryptv2)
nonce0 <- fromJust <$> getNonce leDir.newNonce
postCreateAccount jwk leDir.newAccount nonce0 (createAccount contacts)
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
