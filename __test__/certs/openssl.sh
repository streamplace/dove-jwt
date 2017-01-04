#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

docker run \
  --rm \
  -it \
  -v $(realpath .):/certs \
  -e OPENSSL_CONF=/certs/openssl/openssl.cnf \
  -w /certs \
  centurylink/openssl \
  sh -c "openssl $*"
