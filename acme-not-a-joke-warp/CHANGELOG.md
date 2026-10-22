# Revision history for acme-not-a-joke-warp

## 0.1.0.0 -- unreleased

* TLS-ALPN-01 challenges: `challengeMethod = TlsAlpn01` makes `runAutoHttps`
  get the certificates with challenges answered by the HTTPS server, and
  `serveHttp = False` leaves out the HTTP server (port 80). The HTTPS server
  always answers the TLS-ALPN-01 challenges of its store (`withTlsAlpn01`).
  `acmeTlsAlpn01Issuer` is the issuer doing so.
* `runAutoHttpsWith` gives the issuer `Challenges` (the stores of both
  challenge types, see `newChallenges`) rather than a `ChallengeStore`.

* First version: `Acme.NotAJoke.Warp` with `runAutoHttps`, running a wai
  application over HTTPS (warp-tls) next to an HTTP server which answers
  HTTP-01 challenges and redirects to HTTPS (`redirectToHttps`).
* `Acme.NotAJoke.Warp.CertificateManager`: a `CertificateManager` which
  obtains one certificate per domain when it starts, stores keys and
  certificates on disk, renews the certificates before they expire, hands them
  to the `CertificateStore` of a running warp-tls server, and retries with
  increasing delays when it fails (`runCertificateManager`,
  `checkCertificates`). `acmeIssuer` gets the certificates with an ACME dance;
  failures are reported as `Event`s instead of thrown.
* A README, an example program (behind the `example` flag) and a
  `certificate-manager` test-suite.
