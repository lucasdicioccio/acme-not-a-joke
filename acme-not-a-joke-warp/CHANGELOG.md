# Revision history for acme-not-a-joke-warp

## 0.1.0.0 -- unreleased

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
