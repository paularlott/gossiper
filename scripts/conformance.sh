#!/usr/bin/env bash
# Runs Mercure's conformance suite against gossiper.
#
# The suite (github.com/dunglas/mercure, conformance-tests, AGPL-3.0) is fetched into a temporary directory at run
# time and drives a browser against the hub over HTTP: none of it is part of this repository, nor built into it.
#
#   scripts/conformance.sh [playwright args...]     e.g. --project=chromium
#
# Needs git, Node.js (npm, npx) and a built bin/gossiper (task build). The suite signs with Mercure's development key,
# as issuer https://localhost for the audience https://localhost/.well-known/mercure; the hub is started to match.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${GOSSIPER_BIN:-$root/bin/gossiper}
port=${CONFORMANCE_PORT:-18888}
work=$(mktemp -d)
trap 'kill "${hub:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

git clone --quiet --depth 1 --filter=blob:none --sparse https://github.com/dunglas/mercure "$work/mercure"
git -C "$work/mercure" sparse-checkout set conformance-tests
cd "$work/mercure/conformance-tests"
npm ci --silent
npx playwright install >/dev/null

"$bin" serve --listen "127.0.0.1:$port" --http-only --anonymous --log-level warn \
  --publisher-key '!ChangeThisMercureHubJWTSecretKey!' \
  --resource-identifier https://localhost/.well-known/mercure &
hub=$!
for _ in $(seq 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.1; done

BASE_URL="http://localhost:$port/.well-known/mercure" CUSTOM_ID=1 npx playwright test --reporter=line "$@"
