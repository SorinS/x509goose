#!/bin/sh
# Builds tools/govectors (Go's crypto/x509 and x/crypto/ocsp) offline from the module cache and runs it
# with these arguments; see tools/govectors/main.go.
#
#	tools/govectors.sh > test/vectors/ocsp.txt   # the OCSP vectors (fresh keys each run)
#	tools/govectors.sh pq                         # the Go part of pq.txt (scripts/pq_vectors.py)
#	tools/govectors.sh check <dir>                # check what tools/make_pki.goose made
set -e
dir=$(cd "$(dirname "$0")/govectors" && pwd)
bin=${TMPDIR:-/tmp}/govectors.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
