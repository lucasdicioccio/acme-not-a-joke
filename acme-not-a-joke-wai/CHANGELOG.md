# Revision history for acme-not-a-joke-wai

## 0.1.0.0 -- unreleased

* `Acme.NotAJoke.Wai.TlsAlpn01`: TLS-ALPN-01 challenges (RFC-8737) answered
  by a running warp-tls server, without port 80. A `TlsAlpn01Store` of
  challenge certificates, `withTlsAlpn01` and `tlsAlpn01Hooks` to present them
  to the handshakes asking for `acme-tls/1` (over TLS 1.3), `challengeCredential`
  to create them, and `runAcmeDance_tlsalpn01_wai` and `tlsAlpn01Steps` to fill
  and clear the store during an ACME dance. New dependency: `time`. A
  `tls-alpn-01` test-suite.

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
