{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

module Acme.NotAJoke.LetsEncrypt where

import Acme.NotAJoke.Api.Endpoint

-- Base URL for Let'sEncrypt staging.
staging_letsencryptv2 :: BaseUrl
staging_letsencryptv2 = "https://acme-staging-v02.api.letsencrypt.org/"

-- Base URL for Let'sEncrypt production.
letsencryptv2 :: BaseUrl
letsencryptv2 = "https://acme-v02.api.letsencrypt.org/"
