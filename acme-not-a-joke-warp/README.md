# acme-not-a-joke-warp

Automatic HTTPS for warp, in the spirit of Caddy: runs a wai application over
HTTPS with certificates obtained from an ACME server (e.g. Let's Encrypt),
which are stored on disk, renewed before they expire, and served without
restarting.

Built on [acme-not-a-joke](../README.md) (the ACME client) and
[acme-not-a-joke-wai](../acme-not-a-joke-wai/README.md) (HTTP-01 challenges
and the live certificate store for warp-tls).

```hs
import Acme.NotAJoke.LetsEncrypt (letsencryptv2)
import Acme.NotAJoke.Warp
import Data.List.NonEmpty (NonEmpty (..))

main :: IO ()
main =
  runAutoHttps
    (defaultAutoHttps letsencryptv2 ("example.dicioccio.fr" :| []) ["mailto:certmaster@dicioccio.fr"] "state")
    application
```

Using an ACME server means agreeing to its terms of service: the account is
created saying so.

## what runs

`runAutoHttps` runs three things until one of the servers stops:

- an **HTTPS server** (port 443) running your application. It reads its
  certificate from a `CertificateStore` at each TLS handshake;
- an **HTTP server** (port 80) answering the HTTP-01 challenges of the ACME
  server and redirecting any other request to HTTPS (308). Set
  `httpApplication` to run something else than the redirection;
- a **certificate manager**, which looks after one certificate per domain.

The machine must be reachable from the Internet under each domain, on port 80
(the ACME server connects there, whatever `httpSettings` says: change the port
only when something forwards port 80 to it) and on the HTTPS port.

For each domain, the manager:

1. loads the certificate stored by a previous run, and serves it;
2. when there is none, or when it is due for renewal, runs an ACME dance with
   an HTTP-01 challenge, writes the new certificate on disk and puts it in the
   `CertificateStore`: the next TLS connection gets it, established connections
   are left alone, nothing is restarted;
3. when the dance fails, reports the failure and tries again later.

Until the first certificate is there (a few seconds when all goes well), TLS
handshakes fail: the server has nothing to present.

## when

| what | default | setting (in `ManagerSettings`) |
|------|---------|--------------------------------|
| renewal | when two thirds of the validity period have elapsed (30 days before the end of a 90-days certificate) | `renewAt`, e.g. `renewBefore (20 * 86400)` |
| retry after a failure | 2 minutes, then twice as long after each failure in a row, up to 6 hours | `retryDelay` |
| looking at the clock | at least every hour | `checkInterval` |

A stored certificate which is due for renewal but still valid is served while
the manager tries to renew it. A failure never stops the servers and is not
thrown: errors of the ACME server, network failures, and errors while reading
or writing files all are reported as an `Event` to `onEvent` (which prints a
line on stderr by default).

ACME providers limit the number of failed validations (five per hour and per
name at Let's Encrypt): keep that in mind when changing `retryDelay`, and use
the staging environment (`staging_letsencryptv2`) while testing.

## where things are stored

Everything is in the state directory (the last argument of
`defaultAutoHttps`), which is created if missing:

| file | role |
|------|------|
| `account.jwk` | the ACME account key, created on the first run (and so is the account) |
| `{domain}/key.pem` | the private key of the certificate (RSA, PKCS#1), created on the first run and reused for renewals |
| `{domain}/certificate.pem` | the certificate chain, leaf certificate first, replaced at each renewal |

The CSR is built in memory at each dance. Files are written aside and renamed,
so that a reader never sees half a file. `key.pem` and `certificate.pem` are in
the formats that warp-tls, nginx, haproxy etc. read.

The directory holds private keys and files are created with the default
permissions of the process: restrict who can read the directory.

Removing `{domain}/certificate.pem` makes the manager ask for a new certificate
at the next start. A stored certificate which cannot be parsed, or which is not
for the stored key, is replaced. A key file which cannot be read is left alone:
this is reported as a failure, for you to sort out.

## settings

`defaultAutoHttps` gives an `AutoHttps` record to update:

```hs
let cfg = defaultAutoHttps letsencryptv2 ("example.dicioccio.fr" :| ["www.example.dicioccio.fr"]) contacts "state"
runAutoHttps
  cfg
    { httpsSettings = setPort 8443 defaultSettings
    , managerSettings = cfg.managerSettings{renewAt = renewBefore (20 * 86400), onEvent = myLogger}
    }
  application
```

- `managerSettings`: domains, state directory, renewal and retry times, key
  generation (`generateKey`, RSA-4096 by default), event handler;
- `acmeSettings`: ACME server, path of the account key, contacts, how long an
  order is polled;
- `httpSettings`, `httpsSettings`: the warp settings of both servers;
- `tweakTls`: changes the warp-tls settings (leave the server name indication
  hook alone, it is the one reading the certificates);
- `httpApplication`: what the HTTP server runs besides answering challenges.

With several domains, each one has its own certificate, presented to clients
asking for this name (SNI). The certificate of the first domain also is the
default one.

## running the parts yourself

`runAutoHttps` is a dozen lines assembling parts that you can use directly,
e.g. when the HTTP server on port 80 is not a warp server of this program, or
to keep certificates fresh for something else than warp:

```hs
challenges <- newChallengeStore
certificates <- newCertificateStore
Right manager <-
  newCertificateManager
    (defaultManagerSettings ("example.dicioccio.fr" :| []) "state")
    (acmeIssuer (defaultAcmeSettings letsencryptv2 "state/account.jwk" contacts) challenges)
    certificates

forkIO $ run 80 (http01Middleware challenges (redirectToHttps 443))
forkIO $ runTLS (liveTlsSettings certificates) (setPort 443 defaultSettings) application
runCertificateManager manager
```

`checkCertificates` is a single pass of `runCertificateManager`, and returns
when the next pass is due. An `Issuer` is a function from a domain and a key to
a certificate chain: `acmeIssuer` is the ACME one, the tests use one making
self-signed certificates.

## example

[example/Main.hs](example/Main.hs):

```console
cabal build -fexample acme-not-a-joke-warp-example
sudo $(cabal list-bin -fexample acme-not-a-joke-warp-example) example.dicioccio.fr certmaster@dicioccio.fr ./state
```

It uses the staging environment of Let's Encrypt.

## limits

- HTTP-01 only: no wildcard certificates, and port 80 must be reachable.
- One certificate per domain rather than one certificate for several names
  (the dance of `acme-not-a-joke` validates a single authorization per order).
- Certificate keys are RSA, and the key is reused across renewals.
- The names in a stored certificate are not checked against the domain of its
  directory.
- No OCSP stapling, no revocation, no on-demand certificates for names which
  are not listed.
- One process per state directory: nothing coordinates several instances
  behind a load balancer.
