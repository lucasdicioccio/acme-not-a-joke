module Acme.NotAJoke.Field where

import GHC.TypeLits (Symbol)

type family Field (a :: Symbol) (k :: Symbol) v

