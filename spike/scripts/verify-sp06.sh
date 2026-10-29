#!/usr/bin/env bash
# Checks the SP-06 success criterion (F78-F82): the real Kibana plugin
# obtains a short-lived token (JWT RS256) via Elasticsearch with alice's
# session, and the dummy engine verifies its signature, expiry, and
# audience.
#
# Runtime update (see spike/README.md#sp-06-minimal-kibana-plugin--short-lived-token-dummy-engine):
# the Kibana plugin (spike/kibana-plugin/) was eventually compiled and installed
# in this compose's `kibana` image, after two minor Dockerfile
# fixes and a proxy fix (`X-elastic-product` header, required
# by the official ES client that `asCurrentUser.transport.request` uses
# on the plugin side). This script therefore tests the plugin's real
# server route (`POST /api/spike_ask/ask`) directly, then independently verifies
# with curl the engine's negative vectors (expired token / wrong aud / wrong
# signature), which do not depend on the plugin.
#
# Usage: from spike/, after `docker compose up -d`:
#   ./scripts/verify-sp06.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Missing .env file. Run: cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

COMPOSE=(docker compose -f docker-compose.yml)

wait_for() {
  local description="$1"
  shift
  local tries=30
  until "$@" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      echo "KO: timed out waiting for $description" >&2
      return 1
    fi
    sleep 2
  done
}

echo "== Waiting for the proxy and the dummy engine =="
wait_for "Proxy" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210
wait_for "Dummy engine (engine)" "${COMPOSE[@]}" exec -T proxy curl -sf http://engine:8080/health
echo "OK"
echo

echo "== Anonymous: POST /_spike/identity-token with no header → 401 =="
anon_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9210/_spike/identity-token)
if [ "$anon_code" != "401" ]; then
  echo "KO: expected 401, got $anon_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Service account (elastic): no token for a technical account → 403 =="
svc_code=$(curl -s -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" -X POST http://127.0.0.1:9210/_spike/identity-token)
if [ "$svc_code" != "403" ]; then
  echo "KO: expected 403, got $svc_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Alice: token issued by the proxy (token-via-Elasticsearch variant, F78) =="
alice_token_body=$(curl -sf -u "alice:${ALICE_PASSWORD}" -X POST http://127.0.0.1:9210/_spike/identity-token)
alice_token=$(echo "$alice_token_body" | sed -E 's/.*"token":"([^"]+)".*/\1/')
if [ -z "$alice_token" ] || [ "$alice_token" = "$alice_token_body" ]; then
  echo "KO: no token field in the proxy response" >&2
  echo "$alice_token_body" >&2
  exit 1
fi
echo "OK: token received (truncated): ${alice_token:0:32}..."
echo

echo "== Relay to the dummy engine: signature, expiry, audience (F79) =="
engine_body=$("${COMPOSE[@]}" exec -T proxy curl -s -X POST \
  -H "Authorization: Bearer ${alice_token}" http://engine:8080/whoami)
if ! echo "$engine_body" | grep -q '"sub":"alice"'; then
  echo "KO: the engine did not recognize alice as the token subject" >&2
  echo "$engine_body" >&2
  exit 1
fi
if ! echo "$engine_body" | grep -q 'equipe-a-viewer'; then
  echo "KO: alice's equipe-a-viewer group does not appear in the verified token" >&2
  echo "$engine_body" >&2
  exit 1
fi
if ! echo "$engine_body" | grep -q '"aud":"spike-engine"'; then
  echo "KO: the token audience is not spike-engine" >&2
  echo "$engine_body" >&2
  exit 1
fi
echo "OK: the engine verifies signature + expiry + audience and recovers alice's identity"
echo "    $engine_body"
echo

echo "== Real Kibana plugin: route with no cookie → 401 (not 404, the plugin is loaded) =="
plugin_anon_code=$(curl -s -o /dev/null -w '%{http_code}' -H 'kbn-xsrf: true' -X POST http://127.0.0.1:5601/api/spike_ask/ask)
if [ "$plugin_anon_code" != "401" ]; then
  echo "KO: expected 401 (plugin loaded but unauthenticated), got $plugin_anon_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Real Kibana plugin: alice session → POST /api/spike_ask/ask → 200 =="
plugin_jar=$(mktemp)
trap 'rm -f "$plugin_jar"' EXIT
plugin_login_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$plugin_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$plugin_login_code" != "200" ]; then
  echo "KO: alice's Kibana login failed ($plugin_login_code)" >&2
  exit 1
fi
plugin_body=$(curl -s -b "$plugin_jar" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{}' -X POST http://127.0.0.1:5601/api/spike_ask/ask)
if ! echo "$plugin_body" | grep -q '"sub":"alice"'; then
  echo "KO: the plugin route did not return alice's identity" >&2
  echo "$plugin_body" >&2
  exit 1
fi
if ! echo "$plugin_body" | grep -q 'equipe-a-viewer'; then
  echo "KO: the equipe-a-viewer group does not appear in the plugin response" >&2
  echo "$plugin_body" >&2
  exit 1
fi
echo "OK: the spike_ask plugin (asCurrentUser → proxy → engine) returns alice's identity"
echo "    $plugin_body"
echo

echo "== Negative vectors: forged tokens, the engine must refuse them (F79) =="

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mint_test_jwt builds a JWT RS256 by hand (header.payload.signature),
# without depending on any tool other than openssl: used only to
# forge test vectors that are intentionally invalid (wrong key, exp, or
# aud). The proxy itself uses the github.com/golang-jwt/jwt library
# (see spike/proxy/main.go, mintJWT): the two paths are independent.
mint_test_jwt() {
  local sub="$1" aud="$2" exp="$3" key="$4"
  local header='{"alg":"RS256","typ":"JWT"}'
  local payload
  payload=$(printf '{"sub":"%s","aud":"%s","exp":%s,"iat":%s,"iss":"spike-proxy","groups":["equipe-a-viewer"]}' \
    "$sub" "$aud" "$exp" "$(date +%s)")
  local h p signing_input sig
  h=$(printf '%s' "$header" | b64url)
  p=$(printf '%s' "$payload" | b64url)
  signing_input="$h.$p"
  sig=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key" -binary | b64url)
  printf '%s.%s' "$signing_input" "$sig"
}

check_rejected() {
  local description="$1" token="$2"
  local code
  code=$("${COMPOSE[@]}" exec -T proxy curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${token}" http://engine:8080/whoami)
  if [ "$code" != "401" ]; then
    echo "KO: $description should have been refused (401), got $code" >&2
    exit 1
  fi
  echo "OK: $description refused (401)"
}

now=$(date +%s)
expired_token=$(mint_test_jwt alice spike-engine $((now - 3600)) keys/private.pem)
wrong_aud_token=$(mint_test_jwt alice another-service $((now + 300)) keys/private.pem)
wrong_sig_token=$(mint_test_jwt alice spike-engine $((now + 300)) keys/wrong-private.pem)

check_rejected "expired token" "$expired_token"
check_rejected "wrong audience" "$wrong_aud_token"
check_rejected "wrong signature" "$wrong_sig_token"
echo

echo "== Positive control: a well-formed token with the right key is accepted =="
good_token=$(mint_test_jwt alice spike-engine $((now + 300)) keys/private.pem)
good_code=$("${COMPOSE[@]}" exec -T proxy curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${good_token}" http://engine:8080/whoami)
if [ "$good_code" != "200" ]; then
  echo "KO: a valid token forged with the right key was refused ($good_code)" >&2
  exit 1
fi
echo "OK: accepted (200) — confirms the refusals above come from the token, not some other problem"
echo

echo "== SP-06: success criterion met =="
echo "    Real Kibana plugin loaded and working, token-via-Elasticsearch variant"
echo "    verified end to end (signature, expiry, audience)."
