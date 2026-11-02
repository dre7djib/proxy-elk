#!/usr/bin/env bash
# Checks the one-command demo and the ES relay
# (run_as):
#   1. product proxy: /health, /metrics
#   2. product proxy: LDAPS login -> /auth/me
#   3. product proxy: OIDC smoke (302 redirect to Keycloak)
#   4. Kibana login as alice through the product proxy (the only
#      Kibana -> Elasticsearch path in this demo)
#   5. ES relay: alice reads equipe-a-sample through the proxy, equipe-b-sample
#      is denied (ACL, configs/proxy.yaml)
#   6. Kerberos/SPNEGO SSO: 401+Negotiate without a SPNEGO token, then alice with
#      a real token (kinit from the krb5-user container) through to the
#      ES relay
#
# Usage: from deploy/demo/, after `docker compose up -d`:
#   ./scripts/verify.sh
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

wait_for() {
  local description="$1"
  shift
  local tries=60
  until "$@" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      echo "KO: timed out waiting for $description" >&2
      return 1
    fi
    sleep 2
  done
}

echo "== Waiting for services =="
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "Product proxy" curl -sf http://127.0.0.1:8081/health
wait_for "Keycloak" curl -sf http://127.0.0.1:18080/realms/demo
echo "OK: kibana, proxy, keycloak respond"
echo

echo "== 0. Elasticsearch not reachable directly =="
if curl -s -o /dev/null -m 3 http://127.0.0.1:9200; then
  echo "KO: 127.0.0.1:9200 responded, elasticsearch must not be exposed on the host" >&2
  exit 1
fi
echo "OK: 127.0.0.1:9200 refuses the connection (internal es network)"
echo

echo "== 1. Product proxy: /health and /metrics =="
curl -sf http://127.0.0.1:8081/health >/dev/null
metrics_body=$(curl -sf http://127.0.0.1:8081/metrics)
echo "$metrics_body" | grep -q .
echo "OK"
echo

echo "== 2. Product proxy: LDAPS login alice -> /auth/me =="
cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar"' EXIT
login_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$cookie_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}")
if [ "$login_code" != "302" ]; then
  echo "KO: LDAPS login alice through the product proxy returned $login_code (expected 302)" >&2
  exit 1
fi
me_body=$(curl -s -b "$cookie_jar" http://127.0.0.1:8081/auth/me)
if ! echo "$me_body" | grep -q '"alice"'; then
  echo "KO: /auth/me does not return alice's identity: $me_body" >&2
  exit 1
fi
echo "OK: alice authenticated over LDAPS by the product proxy"
echo

echo "== 2bis. Product proxy: bad password rejected =="
bad_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d '{"username":"alice","password":"wrong"}')
if [ "$bad_code" != "401" ]; then
  echo "KO: bad password returns $bad_code (expected 401)" >&2
  exit 1
fi
echo "OK"
echo

echo "== 3. Product proxy: OIDC smoke (redirect to Keycloak) =="
oidc_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/auth/login")
if [ "$oidc_code" != "302" ] && [ "$oidc_code" != "303" ]; then
  echo "KO: /auth/login returned $oidc_code (expected a redirect to Keycloak)" >&2
  exit 1
fi
echo "OK: /auth/login redirects (code $oidc_code)"
echo

echo "== 4. Kibana login alice (LDAP) through the product proxy =="
kbn_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$kbn_cookie_jar"' EXIT
kbn_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$kbn_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$kbn_http_code" != "200" ]; then
  echo "KO: Kibana returned $kbn_http_code for alice's login through the product proxy" >&2
  exit 1
fi
kbn_me=$(curl -s -b "$kbn_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$kbn_me" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: Kibana does not recognize alice as the current user" >&2
  exit 1
fi
echo "OK: alice signs in to Kibana through the product proxy (only path to Elasticsearch)"
echo

echo "== 4bis. Kibana SSO (/auth/kibana): one login, never the Kibana form =="
sso_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$kbn_cookie_jar" "$sso_cookie_jar"' EXIT
sso_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$sso_cookie_jar" \
  -X POST "http://127.0.0.1:8081/auth/kibana" \
  -d "username=alice&password=${ALICE_PASSWORD}")
if [ "$sso_code" != "302" ]; then
  echo "KO: /auth/kibana returned $sso_code (expected 302)" >&2
  exit 1
fi
sso_me=$(curl -s -b "$sso_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$sso_me" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: the Kibana cookie set by /auth/kibana does not recognize alice: $sso_me" >&2
  exit 1
fi
echo "OK: a single login on the proxy signs alice into Kibana, without its form"
echo

echo "== 5. ES relay (run_as): ACL applied through the product proxy =="
alice_a_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:8081/equipe-a-sample/_count")
if [ "$alice_a_code" != "200" ]; then
  echo "KO: alice cannot read equipe-a-sample through the proxy (code $alice_a_code)" >&2
  exit 1
fi
alice_b_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:8081/equipe-b-sample/_count")
if [ "$alice_b_code" != "403" ]; then
  echo "KO: alice was able to read equipe-b-sample through the proxy (code $alice_b_code, expected 403)" >&2
  exit 1
fi
echo "OK: alice reads equipe-a-sample (run_as), equipe-b-sample is denied (ACL)"
echo

echo "== 6. Kerberos/SPNEGO SSO (/auth/kibana): challenge without a SPNEGO token =="
negotiate_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/auth/kibana")
negotiate_header=$(curl -s -o /dev/null -D - "http://127.0.0.1:8081/auth/kibana" | grep -i '^www-authenticate:' || true)
if [ "$negotiate_code" != "401" ]; then
  echo "KO: GET /auth/kibana without a SPNEGO token returned $negotiate_code (expected 401)" >&2
  exit 1
fi
if ! echo "$negotiate_header" | grep -qi 'Negotiate'; then
  echo "KO: WWW-Authenticate: Negotiate missing from the 401 response: $negotiate_header" >&2
  exit 1
fi
echo "OK: 401 + WWW-Authenticate: Negotiate without a SPNEGO token"
echo

echo "== 6bis. Kerberos/SPNEGO SSO: alice with a real SPNEGO token (krb5-user) =="
docker compose exec -T krb5-user bash -c "echo '${ALICE_PASSWORD}' | kinit alice" >/dev/null
krb_sso_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/auth/kibana")
if [ "$krb_sso_code" != "302" ]; then
  echo "KO: GET /auth/kibana with alice's SPNEGO token returned $krb_sso_code (expected 302)" >&2
  exit 1
fi
krb_count_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/equipe-a-sample/_count")
if [ "$krb_count_code" != "200" ]; then
  echo "KO: ES relay via Negotiate (alice, equipe-a-sample) returned $krb_count_code (expected 200)" >&2
  exit 1
fi
krb_denied_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/equipe-b-sample/_count")
if [ "$krb_denied_code" != "403" ]; then
  echo "KO: ES relay via Negotiate (alice, equipe-b-sample) returned $krb_denied_code (expected 403)" >&2
  exit 1
fi
echo "OK: alice authenticates via Kerberos (real SPNEGO token), ACL applied on the ES relay"
echo

echo "All green: one-command demo is up."
