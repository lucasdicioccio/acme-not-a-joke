# ACME-not-a-joke

A library of primitives to perform ACME authentication certifications [RFC-8555](https://datatracker.ietf.org/doc/html/rfc8555).

## status of this library

Incomplete and subject to changes. But the happy path will work.

What I'd like to change:
- no longer use `wreq` (it returns non-200 with exception)
- support more features
- allow to tweak algos (works for RS256 only)
- better helpers to create/load/write various PKI-related formats

Design-wise, the library uses a TypeFamily pattern to specify/modulate which
fields are available for ACME resources in various APIs/states (e.g., an
`Account` in the `"account-create"` message has no "orders" fields).

## what about the name of the library

We use ACME-not-a-joke as a package name because `acme-` packages on Hackage
typically are "joke" packages.

## todo list

- tweak supported algos
- more functions to save/load jwk/pem
- remove usage of wreq or catch exceptions somehow
- some more doc
- keyChange
- deactivate account
