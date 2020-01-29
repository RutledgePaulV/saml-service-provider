#!/usr/bin/env zsh

if ! command -v saml-idp >/dev/null; then
  echo "Installing saml-idp from source for testing."
  git clone git@github.com:mcguinness/saml-idp.git /tmp/saml-idp
  cd /tmp/saml-idp && npm install && npm link && cd ..
  rm -rf /tmp/saml-idp
fi

saml-idp \
  --acsUrl http://localhost:3000/saml/acs \
  --sloUrl http://localhost:3000/saml/confirm-logout \
  --audience http://localhost:3000 \
  --host localhost \
  --cert ./testfiles/idp-public-cert.pem \
  --key ./testfiles/idp-private-key.pem
