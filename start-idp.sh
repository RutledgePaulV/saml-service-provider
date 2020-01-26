#!/usr/bin/env zsh

saml-idp \
  --acsUrl http://localhost:3000/callback \
  --audience http://localhost:3000 \
  --host localhost \
  --cert ./testfiles/idp-public-cert.pem \
  --key ./testfiles/idp-private-key.pem
