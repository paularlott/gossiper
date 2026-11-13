#!/bin/sh
# Writes the notices of the third-party software in gossiper's binary to stdout (THIRD_PARTY_LICENSES.txt in the
# release archives and the container image): the Go modules it is built from, and the JavaScript bundled into the
# admin API's reference page.
#
# Needs go-licenses (go install github.com/google/go-licenses/v2@v2.0.1) and the web build (web/dist/licenses.md).
set -eu
cd "$(dirname "$0")/.."
if [ ! -s web/dist/licenses.md ]; then
  echo "web/dist/licenses.md is missing: build the web assets first (task webassets)" >&2
  exit 1
fi
echo "Third-party software in gossiper"
echo
echo "Gossiper is MIT licensed (LICENSE.txt). It includes the following software, under the licences given."
echo
echo "Go modules built into the binary:"
go-licenses report --ignore github.com/paularlott/gossiper --template scripts/licenses.tpl ./cmd/gossiper
echo
echo "================================================================================"
echo "JavaScript bundled into the admin API's reference page (/api-docs/):"
echo
cat web/dist/licenses.md
