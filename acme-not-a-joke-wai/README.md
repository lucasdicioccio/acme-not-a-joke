# acme-not-a-joke-wai

Lets a wai/warp application get its own TLS certificates with
[acme-not-a-joke](../README.md), using HTTP-01 challenges (RFC-8555 section
8.3) or TLS-ALPN-01 challenges (RFC-8737), and serve them without restarting.

Three modules, which can be used separately:

- `Acme.NotAJoke.Wai.Http01`: a wai `Middleware` answering the HTTP-01
  challenge, and a dance that tells the middleware what to answer.
- `Acme.NotAJoke.Wai.TlsAlpn01`: TLS settings making a warp-tls server answer
  the TLS-ALPN-01 challenge on port 443 (no port 80 needed), and a dance that
  tells the server what to answer.
- `Acme.NotAJoke.Wai.WarpTLS`: a certificate store that a warp-tls server
  reads at each TLS handshake, so that a new certificate is served live.

## who initiates what

Nothing is automatic: **your program is the ACME client**. It decides when to
get a certificate by calling `runAcmeDance_http01_wai`, which blocks until the
dance is over. The library has no background thread and no renewal timer.

```
your program                              ACME server (e.g. Let's Encrypt)
     |                                              |
     |  1. account, new order, authorization        |
     |--------------- HTTPS, outgoing ------------->|
     |                                              |
     |  2. key authorization put in ChallengeStore  |
     |     "please validate the challenge"          |
     |--------------- HTTPS, outgoing ------------->|
     |                                              |
     |  3. GET /.well-known/acme-challenge/{token}  |
     |<---------- HTTP on port 80, incoming --------|
     |     answered by http01Middleware             |
     |                                              |
     |  4. poll the order, send the CSR,            |
     |     download the certificate chain           |
     |--------------- HTTPS, outgoing ------------->|
     |                                              |
     |  5. handleStep (Done _ certificate)          |
```

Consequences:

- the HTTP server wrapped with `http01Middleware` must already be running on
  port 80, and reachable from the Internet under the domain of the order,
  before the dance starts;
- step 3 is the only incoming request, and it is plain HTTP: if your HTTP
  server redirects everything to HTTPS, the middleware must wrap the
  redirection;
- the dance is over in a few seconds when all goes well. Your `handleStep`
  decides how long to wait between two polls (the `WaitingForValidation n`
  step, `n` being the number of polls so far);
- renewing is running the dance again, e.g. from a thread that sleeps until
  some weeks before the certificate expires.

## where things are stored

The library writes no file on its own. Both stores (`ChallengeStore`,
`CertificateStore`) are in memory. What goes to disk, and where, is decided by
the functions your program calls:

| what | role | who creates it | typical helper |
|------|------|----------------|----------------|
| account key (JWK) | signs the requests to the ACME server, identifies your ACME account | you, once | `loadOrCreateJWKFile "state/account.jwk"` |
| certificate key (RSA, PEM) | the private key of the TLS server; signs the CSR; never leaves the machine | you, once (or at each renewal) | `loadOrCreateRSAKeyPEM "state/key.pem"` |
| CSR | tells the ACME server which names and which public key to certify | you, before each dance | `createCSR key names`, in memory; `writeCSRPEM` only if you want a copy |
| key authorization | the answer to the challenge | the dance | in memory, in the `ChallengeStore`, removed when the dance ends |
| certificate chain (PEM) | what the TLS server presents | the ACME server; given to your `handleStep` in the `Done` step | `storeCert "state/certificate.pem" cert` and `installCertificate store key cert` |

The helpers are in `Acme.NotAJoke.KeyManagement`,
`Acme.NotAJoke.CertManagement` and `Acme.NotAJoke.Api.Certificate` of the
`acme-not-a-joke` package. The paths are yours: nothing has a default
location. Keep the account key and the certificate key private (the helpers
create files with the default permissions of the process).

`certificate.pem` (leaf certificate first, then the intermediates) and
`key.pem` are in the formats that `warp-tls`, nginx, haproxy etc. read.

## serving the certificate live with warp-tls

`Network.Wai.Handler.WarpTLS.tlsSettings` reads the certificate files once,
when the server starts. Instead, start the HTTPS server on a
`CertificateStore`:

```hs
certificates <- newCertificateStore
forkIO $ runTLS (liveTlsSettings certificates) (setPort 443 defaultSettings) application
```

and put a credential in the store whenever you have one:

- `installCertificate certificates key cert` in the `Done` step of a dance;
- `setCredential certificates =<< loadCredential "state/certificate.pem" "state/key.pem"`
  (modulo the `Either`) at startup, to reuse the certificate of a previous run.

The store is read at each TLS handshake: the next connection gets the new
certificate, established connections are left alone, and the server is not
restarted. While the store is empty, TLS handshakes fail (there is nothing to
present); the HTTP server on port 80 is not affected, so the first dance can
run.

A server with several certificates uses `setCredentialFor store "name" cred`:
the store then picks the credential from the server name (SNI) asked by the
client, and falls back to the one set with `setCredential`.

`liveTlsSettings` is `tlsSettingsSni` from warp-tls (3.4.13 or later) applied to
`sniCredentials`, which you can call from your own TLS hooks.

## tls-alpn-01 challenges, without port 80

With a TLS-ALPN-01 challenge, the ACME server opens a TLS connection to port
443 of the domain asking for the `acme-tls/1` protocol (ALPN), and expects a
self-signed certificate carrying the digest of the key authorization. The
HTTPS server answers it itself: no HTTP server is needed.

```hs
challenges <- newTlsAlpn01Store
certificates <- newCertificateStore
forkIO $ runTLS (withTlsAlpn01 challenges (liveTlsSettings certificates)) (setPort 443 defaultSettings) application

runAcmeDance_tlsalpn01_wai challenges dancer
```

`withTlsAlpn01` wraps the server hooks: handshakes asking for `acme-tls/1`
get the challenge certificate of the store for their server name, the other
ones are untouched (they get the certificates of the live store, and `h2` or
`http/1.1`). `runAcmeDance_tlsalpn01_wai` creates the challenge certificate
(with a throw-away RSA-2048 key) when the ACME server gives the challenge, and
removes it when the dance is over. `challengeCredential`, `insertTlsAlpn01`
and `deleteTlsAlpn01` do the same by hand.

The server must keep its TLS 1.3 support enabled (the default of warp-tls):
the `tls` library chooses the certificate before the protocol with TLS 1.2,
so the challenge is only answered over TLS 1.3, which ACME servers use.

## complete example

[example/Main.hs](example/Main.hs) is a warp server doing all of the above:
keys created on the first run, HTTP on port 80 with the middleware, HTTPS on
port 443 with the live store, certificate requested when there is none on disk,
then written to disk and served.

```console
cabal build -fexample acme-not-a-joke-wai-example
sudo $(cabal list-bin -fexample acme-not-a-joke-wai-example) example.dicioccio.fr certmaster@dicioccio.fr ./state
```

It uses the staging environment of Let's Encrypt. The essential part:

```hs
accountKey <- orDie =<< loadOrCreateJWKFile "state/account.jwk"
key <- orDie =<< loadOrCreateRSAKeyPEM "state/key.pem"
csr <- orDie =<< createCSR key ("example.dicioccio.fr" :| [])

challenges <- newChallengeStore
certificates <- newCertificateStore
forkIO $ run 80 (http01Middleware challenges application)
forkIO $ runTLS (liveTlsSettings certificates) (setPort 443 defaultSettings) application

let handle step = case step of
      WaitingForValidation n -> threadDelay (n * 1000000)
      Done _ cert -> do
        storeCert "state/certificate.pem" cert
        orDie =<< installCertificate certificates key cert
      _ -> pure ()

runAcmeDance_http01_wai challenges $
  AcmeDancer
    staging_letsencryptv2
    accountKey
    (fetchAccount1 True False ["mailto:certmaster@dicioccio.fr"])
    csr
    (createOrder (Nothing, Nothing) [OrderIdentifier DNSOrder "example.dicioccio.fr"])
    handle
```

`fetchAccount1 True False` creates the ACME account if the account key has
none yet (and agrees to the terms of service of the ACME server); `fetchAccount`
only accepts an existing account.

## limits

- HTTP-01 and TLS-ALPN-01 cannot validate wildcard identifiers: these need
  DNS-01.
- TLS-ALPN-01 challenges are answered over TLS 1.3 only.
- The dance validates the first authorization of an order only: one
  certificate per name, rather than one certificate for several names.
- No renewal scheduling, no rate-limit handling: failures are reported to
  `handleStep` (`InvalidOrder`, `OtherError`, `AcmeFailure`) and the dance
  stops. The
  [acme-not-a-joke-warp](../acme-not-a-joke-warp/README.md) package has a
  certificate manager doing the scheduling (startup, renewals, retries) on
  top of this package.
- Certificate keys are RSA.
