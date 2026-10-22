# Revision history for acme-not-a-joke

## 0.2.0.0 -- unreleased

* TLS-ALPN-01 challenges (RFC-8737): `isTLSALPN01` (in
  `Acme.NotAJoke.Api.Challenge`), `runAcmeDance_tlsalpn01` (in
  `Acme.NotAJoke.Dancer`), and `createTLSALPN01Certificate`,
  `acmeIdentifierDigest`, `acmeIdentifierOID` and `acmeTLSALPNProtocol` (in
  `Acme.NotAJoke.CertManagement`) to build the self-signed certificate with
  the `acmeIdentifier` extension. New dependency: `time-hourglass`.

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
  application, and hands the certificates to a running warp-tls server.

* Wildcard certificates: orders with several identifiers, such as
  `*.example.com` together with `example.com`, are validated with one challenge
  per authorization (wildcard authorizations need DNS-01). Add
  `dns01RecordName`, `wildcardBase`, `isWildcardDomain` and `pickChallenges`
  (in `Acme.NotAJoke.Client`).
* Breaking: `AcmeSingle` has a `pendingAuthorizations :: [AcmeAuthorization]`
  field in place of `fetchAuthorization`, `proof`, `replyChallenge` and
  `pollChallenge`, which moved to `AcmeAuthorization` (along with the
  identifier and wildcard flag of the authorization). `prepareAcmeOrder`
  inspects every authorization of the order (emitting one `GotAuthorization`
  each) instead of the first one only, and skips the valid ones.
* Breaking: `DanceStep` has a new `Authorizing` constructor, emitted before the
  `Validation` step of each authorization; `runAcmeDance` emits all the
  `Validation` steps before telling the server to check the challenges.
* Certificate revocation (RFC-8555 section 7.6): add
  `Acme.NotAJoke.Api.Revocation` with `Revocation`, `RevocationReason`,
  `revocation`, `revocationDER`, `postRevokeCertificate` (signed with the
  account key) and `postRevokeCertificateWithCertKey` (signed with the key of
  the certificate), and `revokeCertificate` and `revokeCertificateWithCertKey`
  (in `Acme.NotAJoke.Client`), which fetch the directory, nonce and account.
* JWS algorithms beyond RS256: `jwkSign` and `kidSign` sign with the algorithm
  that fits the key (`RS256` for RSA, `ES256`/`ES384`/`ES512`/`ES256K` for EC,
  `EdDSA` for Ed25519/Ed448), or with the algorithm pinned in the `alg`
  parameter of the JWK. Symmetric keys and the `none`/MAC algorithms are
  refused (a `SigningFailed`). Add `acmeJWSAlg`, `acmeProtectedHeader` and
  `setAcmeJWSAlg` (in `Acme.NotAJoke.Api.JWS`) and `genJWKecP256`,
  `genJWKecP384` and `genJWKed25519` (in `Acme.NotAJoke.KeyManagement`). RSA
  keys without a pinned algorithm still sign with `RS256`. New dependency:
  `mtl`.

## 0.1.1.0 -- unreleased

Helpers to create, load and write the PKI formats involved in getting a
certificate, so that `openssl` and `scripts/gen-csr.sh` no longer are required.
Existing functions keep their types.

* `Acme.NotAJoke.KeyManagement`: add `genRSAKey` and `genRSAKey4096` to
  generate the key of a certificate; `encodeRSAKeyPEM`, `decodeRSAKeyPEM`,
  `encodeRSAKeyDER`, `decodeRSAKeyDER`, `loadRSAKeyPEM` and `writeRSAKeyPEM` to
  read and write RSA keys (PKCS#1 is written, PKCS#1 and unencrypted PKCS#8 are
  read); `jwkFromRSAKey` and `jwkToRSAKey` to convert between RSA keys and
  JWKs; `loadOrCreateJWKFile` and `loadOrCreateRSAKeyPEM` to generate a key on
  the first run.
* `Acme.NotAJoke.CertManagement`: add `createCSR` and `createCSRWith` to build
  and sign (RSA with SHA-256) a CSR with its subject alternative names;
  `loadCSR` (PEM or DER files), `writeCSRDER`, `writeCSRPEM`, `csrFromDER`,
  `csrToDER`, `encodeCSRPEM` and `decodeCSRPEM` to read and write CSRs;
  `certificateChain`, `decodeCertificateChain`, `encodeCertificateChain`,
  `loadCertificateChain` and `writeCertificateChain` to parse and write the
  certificates returned by the ACME server.
* Both modules now have an explicit export list (all the functions they had
  still are exported).
* New dependencies: `crypton`, `crypton-x509`, `crypton-asn1-encoding`,
  `crypton-asn1-types`, `crypton-pem` and `directory`. The `crypton` packages
  already were transitive dependencies (via `jose`).
* Add a `pki-formats` test-suite.

## 0.1.0.0 -- YYYY-mm-dd

* First version. Released on an unsuspecting world.
