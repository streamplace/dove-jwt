#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

docker run \
  --rm \
  -it \
  -v $(realpath .):/certs \
  -e OPENSSL_CONF=/certs/Fake_Root_Certificate_Authority.cnf \
  -w /certs \
  centurylink/openssl \
  sh -c "openssl $*"
