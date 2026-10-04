# Revision history for acme-not-a-joke-wai

## 0.1.0.0 -- unreleased

* First version: `Acme.NotAJoke.Wai.Http01` with a `ChallengeStore`, the
  `http01Middleware` answering `GET /.well-known/acme-challenge/{token}`, and
  `runAcmeDance_http01_wai` and `http01Steps` to fill and clear the store
  during an ACME dance.
* `Acme.NotAJoke.Wai.WarpTLS`: a `CertificateStore` read by warp-tls at each
  TLS handshake (`liveTlsSettings`, `sniCredentials`), so that certificates are
  served without restarting; `installCertificate`, `credentialFromCertificate`,
  `credentialFromPEM` and `loadCredential` to fill it. New dependencies:
  `warp-tls` (3.4.13 or later), `tls`, `crypton` and `crypton-x509`.
* A README telling who initiates which request and where keys, CSRs and
  certificates are stored, and an example program (behind the `example` flag).
