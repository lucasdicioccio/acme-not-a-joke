{- | The 'Field' type family, which shapes the records of ACME resources
according to the message or state they are used in.

An ACME resource does not carry the same fields in every message. An account
sent to create the account has a @contact@ but no @status@ (the server has not
decided it yet); an order the server returns has @authorizations@ and a
@finalize@ URL that the client does not send; the @certificate@ URL of an
order only shows up once the order is valid.

Rather than one record per message, the library has one record per resource,
holding every field the resource can have, where each field type goes through
'Field'. The record takes a type-level string (a 'Symbol') naming the state,
and each state picks, field by field, what the field holds:

* @x@: the field is present, with its value
* @()@: the field is absent in this state (there is nothing to read, and
  @()@ is the only thing to put when building the record)
* @Maybe x@: the field may or may not be present (e.g., the @certificate@ of
  an inspected order)

For instance, 'Acme.NotAJoke.Api.Order.Order' has (among others) these
states:

* @Order "order-create"@: what the client sends, built with
  'Acme.NotAJoke.Api.Order.createOrder'; the identifiers and validity
  dates are present, the fields set by the server are @()@
* @Order "order-created"@: what the server replies to a new order (see
  'Acme.NotAJoke.Api.Order.readOrderCreated'), with its status,
  authorizations and finalize URL
* @Order "order-inspected"@: what the server replies when the client polls
  an order (see 'Acme.NotAJoke.Api.Order.readOrderInspected'), where
  @certificate@ is a @Maybe@

The instances live next to the record, one per state and field:

@
data Account a = Account
    { status :: Field a \"status\" AccountStatus
    , contact :: Field a \"contact\" [Contact]
    , ...
    }

type instance Field \"account-create\" \"contact\" x = x
type instance Field \"account-create\" \"status\" x = ()
@

Hence @(createAccount contacts).status :: ()@: the type tells you which
fields make sense in which message, and the functions sending or reading a
message take or return the record in the matching state (e.g.,
'Acme.NotAJoke.Api.Account.postCreateAccount' takes an
@Account \"account-create\"@). The JSON (de)serialization of each state is
written by hand, next to the instances.

States in use: @\"account-create\"@ and @\"account-fetch\"@ for
'Acme.NotAJoke.Api.Account.Account'; @\"order-create\"@,
@\"order-created\"@ and @\"order-inspected\"@ for
'Acme.NotAJoke.Api.Order.Order'; @\"authorization-inspected\"@ for
'Acme.NotAJoke.Api.Authorization.Authorization'; and
@\"challenge-unspecified\"@ for 'Acme.NotAJoke.Api.Challenge.Challenge'.
-}
module Acme.NotAJoke.Api.Field where

import GHC.TypeLits (Symbol)

{- | A type-family to help with REST-APIs where representation of a "same"
object depends heavily on a state.

Allows to define a large product type of all possible fields of a REST
resource on one hand. And specialize the structure based on the state.

@Field state key valuetype@ is the type of the field named @key@, whose value
has type @valuetype@ when present, in the given @state@ (see the module
documentation).
-}
type family Field (state :: Symbol) (key :: Symbol) valuetype
