module Acme.NotAJoke.Api.Field where

import GHC.TypeLits (Symbol)

{- | A type-family to help with REST-APIs where representation of a "same"
object depends heavily on a state.

Allows to define a large product type of all possible fields of a REST
resource on one hand. And specialize the structure based on the state.
-}
type family Field (state :: Symbol) (key :: Symbol) valuetype
