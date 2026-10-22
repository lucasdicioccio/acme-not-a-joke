{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

{- | Base URLs of the Let's Encrypt ACME servers.

Use the staging server while developing: its certificates are not trusted by
browsers, but its rate limits are much higher. Any other ACME server works
the same, given its base URL (the URL of its directory without
@directory@).
-}
module Acme.NotAJoke.LetsEncrypt where

import Acme.NotAJoke.Api.Endpoint

-- | Base URL for Let'sEncrypt staging.
staging_letsencryptv2 :: BaseUrl
staging_letsencryptv2 = "https://acme-staging-v02.api.letsencrypt.org/"

-- | Base URL for Let'sEncrypt production.
letsencryptv2 :: BaseUrl
letsencryptv2 = "https://acme-v02.api.letsencrypt.org/"
