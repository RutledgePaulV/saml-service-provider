#!/usr/bin/env bash

start=$PWD

if ! command -v saml-idp >/dev/null; then
  echo "Installing saml-idp from source for testing."
  rm -rf ~/.saml-idp
  mkdir ~/.saml-idp
  git clone git@github.com:mcguinness/saml-idp.git ~/.saml-idp
  # shellcheck disable=SC2164
  cd ~/.saml-idp && npm install && npm link && cd "$start"
fi

saml-idp \
  --acsUrl http://localhost:3000/saml/acs \
  --sloUrl http://localhost:3000/saml/confirm-logout \
  --audience http://localhost:3000 \
  --host localhost \
  --cert ./testfiles/idp-public-cert.pem \
  --key ./testfiles/idp-private-key.pem
