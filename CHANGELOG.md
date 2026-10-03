# Revision history for microdns

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
