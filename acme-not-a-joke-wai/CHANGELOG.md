# Revision history for acme-not-a-joke-wai

## 0.1.0.0 -- unreleased

* First version: `Acme.NotAJoke.Wai.Http01` with a `ChallengeStore`, the
  `http01Middleware` answering `GET /.well-known/acme-challenge/{token}`, and
  `runAcmeDance_http01_wai` and `http01Steps` to fill and clear the store
  during an ACME dance.
