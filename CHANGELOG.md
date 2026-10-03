# Revision history for acme-not-a-joke

## 0.2.0.0 -- unreleased

ACME errors are now returned as values rather than thrown (or printed), which
changes the type of most API calls.

* Replace `wreq` with `http-client` and `http-client-tls`: non-2xx responses
  are no longer thrown as exceptions. Network-level failures still are raised
  as `HttpException` (from `http-client`).
* Add `AcmeError` (in `Acme.NotAJoke.Api.Endpoint`) with `SigningFailed`,
  `ServerRejected` and `UnexpectedResponse`, and the helpers `errorResponse`,
  `readProblem`, `problemType` and `problemDetail` to read the RFC-7807
  problem document of a rejected request.
* Breaking: the `post*` API calls, `getNonce`, the `Nonce.Fetcher` fields,
  `saveNonce` and `AcmePrim` use `Either AcmeError a` where they had `Maybe a`.
  Signing errors are returned (as `SigningFailed`) instead of printed on stdout.
* Breaking: `fetchDirectory` and `Endpoint.get` return an `Either AcmeError`.
* Breaking: `prepareAcmeOrder` returns an `Either AcmeError AcmeSingle` instead
  of failing with a pattern-match error when a step fails.
* Breaking: `DanceStep` has a new `AcmeFailure` constructor, `runAcmeDance`
  reports failed API calls with it instead of crashing.
* Breaking: the response newtypes (`AccountCreated`, `OrderCreated`,
  `Certificate` etc.) wrap an `Endpoint.Response` (an `http-client` response)
  rather than a `wreq` one.
* Breaking: remove `wrequrl`, `responseNonceWreq` and `responseNonceWreqBS`;
  add `rawResponseNonce`, `responseHeader`, `call`, `head_`, `postJose`,
  `postJoseWith` and `checkResponse`.
* Nonces from error responses are saved for the next request as well.
* Requests carry a `User-Agent` header, as required by RFC-8555.
* Add `isHTTP01` (in `Acme.NotAJoke.Api.Challenge`) and `runAcmeDance_http01`
  (in `Acme.NotAJoke.Dancer`) to validate orders with HTTP-01 challenges. The
  new `acme-not-a-joke-wai` package serves these challenges from a wai
  application.

## 0.1.0.0 -- YYYY-mm-dd

* First version. Released on an unsuspecting world.
