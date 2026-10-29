#!/usr/bin/env bash
# Checks the success criteria for SP-01 to SP-04:
# - Kibana accepts a native login, OpenLDAP contains alice, bob, carol
#   with their team groups (SP-01);
# - the proxy between Kibana and Elasticsearch is a transparent passthrough,
#   and login/Discover work through it (SP-02);
# - Alice logs into Kibana with her LDAP password and appears with
#   her own identity and role (run_as), a wrong password is
#   refused, and the native elastic login still works (SP-03);
# - ES roles and Kibana spaces per team (SP-04): alice (equipe_a_viewer)
#   only sees the equipe-a space in read-only and equipe-a-* data, bob
#   (equipe_a_editor) can edit a dashboard in the equipe-a space, carol
#   (equipe_b_viewer) sees neither the equipe-a space nor its data.
#
# Usage: from spike/, after `docker compose up -d`:
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

echo "== Waiting for services =="
wait_for "Elasticsearch" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200
wait_for "Proxy (SP-02)" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "OpenLDAP" "${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" -w "${LDAP_ADMIN_PASSWORD}"
echo "OK: all four services respond"
echo

echo "== Elasticsearch: native elastic login =="
curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200 >/dev/null
echo "OK"
echo

echo "== Proxy (SP-02): transparent passthrough =="
es_body=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200)
proxy_body=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210)
if [ "$es_body" != "$proxy_body" ]; then
  echo "KO: response via the proxy differs from Elasticsearch directly" >&2
  echo "--- Elasticsearch ---" >&2
  echo "$es_body" >&2
  echo "--- Proxy ---" >&2
  echo "$proxy_body" >&2
  exit 1
fi
echo "OK: identical response direct and via the proxy (transparent passthrough)"
echo

echo "== Proxy (SP-02): authenticated search (Discover-like) =="
search_code=$(curl -s -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" \
  "http://127.0.0.1:9210/_search?size=0")
if [ "$search_code" != "200" ]; then
  echo "KO: a search via the proxy returned $search_code" >&2
  exit 1
fi
echo "OK: authenticated search via the proxy succeeded (status 200)"
echo

echo "== Kibana: native elastic login via the internal API =="
cookie_jar=$(mktemp)
response_body=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body"' EXIT

http_code=$(curl -s -o "$response_body" -w '%{http_code}' \
  -c "$cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"elastic\",\"password\":\"${ELASTIC_PASSWORD}\"}}")

if [ "$http_code" != "200" ]; then
  echo "KO: Kibana returned $http_code on /internal/security/login" >&2
  cat "$response_body" >&2
  exit 1
fi
if ! grep -q "sid" "$cookie_jar"; then
  echo "KO: no session cookie in Kibana's response" >&2
  exit 1
fi
echo "OK: elastic/\$ELASTIC_PASSWORD authenticated by Kibana (session cookie received)"
echo "    Visual check recommended: http://127.0.0.1:5601"
echo

echo "== OpenLDAP: test users =="
"${COMPOSE[@]}" exec -T openldap ldapsearch -x -H ldap://localhost:389 \
  -D "cn=readonly,dc=example,dc=org" -w "${LDAP_READONLY_PASSWORD}" \
  -b "ou=people,dc=example,dc=org" "(uid=*)" uid cn 2>/dev/null | grep -E '^(dn|uid|cn): '
echo

echo "== OpenLDAP: team groups =="
"${COMPOSE[@]}" exec -T openldap ldapsearch -x -H ldap://localhost:389 \
  -D "cn=readonly,dc=example,dc=org" -w "${LDAP_READONLY_PASSWORD}" \
  -b "ou=groups,dc=example,dc=org" "(objectClass=groupOfNames)" cn member 2>/dev/null | grep -E '^(dn|cn|member): '
echo

echo "== OpenLDAP: bind alice with her LDAP password =="
"${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=people,dc=example,dc=org" -w "${ALICE_PASSWORD}" >/dev/null
echo "OK: alice bind succeeded"
echo

echo "== OpenLDAP: bind refused with a wrong password =="
if "${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=people,dc=example,dc=org" -w "mauvais-mot-de-passe" >/dev/null 2>&1; then
  echo "KO: the bind should have been refused" >&2
  exit 1
fi
echo "OK: bind refused as expected"
echo

echo "== Proxy (SP-03/SP-04): Elasticsearch sees alice's identity via run_as =="
authn_body=$(curl -s -u "alice:${ALICE_PASSWORD}" http://127.0.0.1:9210/_security/_authenticate)
if ! echo "$authn_body" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: _authenticate via the proxy does not return alice's identity" >&2
  echo "$authn_body" >&2
  exit 1
fi
if ! echo "$authn_body" | grep -q '"equipe_a_viewer"'; then
  echo "KO: alice's equipe_a_viewer role does not appear in _authenticate" >&2
  echo "$authn_body" >&2
  exit 1
fi
echo "OK: Elasticsearch authenticates alice (run_as), equipe_a_viewer role present (SP-04)"
echo

echo "== Proxy (SP-03): wrong LDAP password refused by Elasticsearch =="
bad_ldap_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:mauvais-mot-de-passe" \
  http://127.0.0.1:9210/_security/_authenticate)
if [ "$bad_ldap_code" != "401" ]; then
  echo "KO: a wrong LDAP password via the proxy returned $bad_ldap_code (expected 401)" >&2
  exit 1
fi
echo "OK: wrong LDAP password refused (401) before reaching Elasticsearch"
echo

echo "== Kibana (SP-03): alice logs in with her LDAP password =="
alice_cookie_jar=$(mktemp)
alice_response_body=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body" "$alice_cookie_jar" "$alice_response_body"' EXIT

alice_http_code=$(curl -s -o "$alice_response_body" -w '%{http_code}' \
  -c "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")

if [ "$alice_http_code" != "200" ]; then
  echo "KO: Kibana returned $alice_http_code on alice's login" >&2
  cat "$alice_response_body" >&2
  exit 1
fi
if ! grep -q "sid" "$alice_cookie_jar"; then
  echo "KO: no session cookie for alice" >&2
  exit 1
fi
echo "OK: alice/\$ALICE_PASSWORD authenticated by Kibana via LDAP (session cookie received)"

me_body=$(curl -s -b "$alice_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$me_body" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: Kibana does not recognize alice as the current user" >&2
  echo "$me_body" >&2
  exit 1
fi
if ! echo "$me_body" | grep -q '"equipe_a_viewer"'; then
  echo "KO: alice's equipe_a_viewer role does not appear on the Kibana side" >&2
  echo "$me_body" >&2
  exit 1
fi
echo "OK: Kibana shows alice's identity and role (SP-03 success criterion)"
echo "    Visual check recommended: http://127.0.0.1:5601, user menu = Alice Martin"
echo

echo "== Kibana (SP-03): wrong LDAP password refused =="
alice_bad_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d '{"providerType":"basic","providerName":"basic","currentURL":"/","params":{"username":"alice","password":"mauvais-mot-de-passe"}}')
if [ "$alice_bad_code" = "200" ]; then
  echo "KO: Kibana should have refused alice's wrong password" >&2
  exit 1
fi
echo "OK: wrong password refused by Kibana ($alice_bad_code)"
echo

echo "== Regression: native elastic login still works through the proxy =="
elastic_regression_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"elastic\",\"password\":\"${ELASTIC_PASSWORD}\"}}")
if [ "$elastic_regression_code" != "200" ]; then
  echo "KO: native elastic login regressed ($elastic_regression_code)" >&2
  exit 1
fi
echo "OK: elastic still logs in directly (without going through LDAP, SP-01/SP-02 not regressed)"
echo

echo "== Waiting for the kibana-setup service (SP-04) =="
kibana_setup_tries=30
until "${COMPOSE[@]}" ps -a kibana-setup --format '{{.State}}' 2>/dev/null | grep -q '^exited$'; do
  kibana_setup_tries=$((kibana_setup_tries - 1))
  if [ "$kibana_setup_tries" -le 0 ]; then
    echo "KO: kibana-setup did not finish in time" >&2
    exit 1
  fi
  sleep 2
done
kibana_setup_exit=$("${COMPOSE[@]}" ps -a kibana-setup --format '{{.ExitCode}}')
if [ "$kibana_setup_exit" != "0" ]; then
  echo "KO: kibana-setup failed (code $kibana_setup_exit): see 'docker compose logs kibana-setup'" >&2
  exit 1
fi
echo "OK: kibana-setup finished successfully (equipe-a/equipe-b spaces and roles ready)"
echo

echo "== Kibana (SP-04): bob (team A, editor) logs in =="
bob_cookie_jar=$(mktemp)
carol_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body" "$alice_cookie_jar" "$alice_response_body" "$bob_cookie_jar" "$carol_cookie_jar"' EXIT
bob_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$bob_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"bob\",\"password\":\"${BOB_PASSWORD}\"}}")
if [ "$bob_http_code" != "200" ]; then
  echo "KO: Kibana returned $bob_http_code on bob's login" >&2
  exit 1
fi
echo "OK: bob authenticated by Kibana"
echo

echo "== Kibana (SP-04): carol (team B, viewer) logs in =="
carol_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$carol_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"carol\",\"password\":\"${CAROL_PASSWORD}\"}}")
if [ "$carol_http_code" != "200" ]; then
  echo "KO: Kibana returned $carol_http_code on carol's login" >&2
  exit 1
fi
echo "OK: carol authenticated by Kibana"
echo

echo "== Kibana (SP-04): alice sees only the equipe-a space =="
alice_spaces=$(curl -s -b "$alice_cookie_jar" http://127.0.0.1:5601/api/spaces/space)
if ! echo "$alice_spaces" | grep -q '"id":"equipe-a"'; then
  echo "KO: alice does not see the equipe-a space" >&2
  echo "$alice_spaces" >&2
  exit 1
fi
if echo "$alice_spaces" | grep -q '"id":"equipe-b"'; then
  echo "KO: alice sees the equipe-b space, which should be invisible to her" >&2
  echo "$alice_spaces" >&2
  exit 1
fi
echo "OK: alice only sees the equipe-a space"
echo

echo "== Kibana (SP-04): alice reads the dashboard in the equipe-a space =="
alice_dashboard_get=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a")
if [ "$alice_dashboard_get" != "200" ]; then
  echo "KO: alice could not read team A's dashboard (code $alice_dashboard_get)" >&2
  exit 1
fi
echo "OK: alice reads team A's dashboard"
echo

echo "== Kibana (SP-04): alice (viewer) CANNOT edit A's dashboard =="
alice_dashboard_put=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a" \
  -d '{"attributes":{"title":"Read-only attempt (should fail)"}}')
if [ "$alice_dashboard_put" != "403" ]; then
  echo "KO: alice (viewer) was able to edit A's dashboard (code $alice_dashboard_put, expected 403)" >&2
  exit 1
fi
echo "OK: alice (viewer) cannot edit A's dashboard (403)"
echo

echo "== Kibana (SP-04): alice (base read) has no access to Dev Tools =="
alice_devtools_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' \
  -X POST "http://127.0.0.1:5601/api/console/proxy?path=_search&method=GET")
if [ "$alice_devtools_code" != "403" ]; then
  echo "KO: alice (viewer, base read) accessed Dev Tools (code $alice_devtools_code, expected 403)" >&2
  exit 1
fi
echo "OK: Dev Tools refused to alice by base:read alone (F75 finding: no custom feature privileges needed)"
echo

echo "== Kibana (SP-04): bob (editor) can edit A's dashboard =="
bob_dashboard_put=$(curl -s -o /dev/null -w '%{http_code}' -b "$bob_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a" \
  -d '{"attributes":{"title":"Team A dashboard modified by bob (verify.sh)"}}')
if [ "$bob_dashboard_put" != "200" ]; then
  echo "KO: bob (editor) could not edit A's dashboard (code $bob_dashboard_put)" >&2
  exit 1
fi
echo "OK: bob (editor) edits A's dashboard (SP-04 success criterion)"
echo

echo "== Kibana (SP-04): carol only sees the equipe-b space, not equipe-a =="
carol_spaces=$(curl -s -b "$carol_cookie_jar" http://127.0.0.1:5601/api/spaces/space)
if echo "$carol_spaces" | grep -q '"id":"equipe-a"'; then
  echo "KO: carol sees the equipe-a space, which should be invisible to her" >&2
  echo "$carol_spaces" >&2
  exit 1
fi
if ! echo "$carol_spaces" | grep -q '"id":"equipe-b"'; then
  echo "KO: carol does not see her own equipe-b space" >&2
  echo "$carol_spaces" >&2
  exit 1
fi
echo "OK: carol only sees the equipe-b space"
echo

echo "== Kibana (SP-04): carol has no direct access to A's space or dashboard =="
carol_space_a_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$carol_cookie_jar" \
  "http://127.0.0.1:5601/api/spaces/space/equipe-a")
if [ "$carol_space_a_code" != "403" ]; then
  echo "KO: carol was able to access the equipe-a space (code $carol_space_a_code, expected 403)" >&2
  exit 1
fi
carol_dashboard_a_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$carol_cookie_jar" \
  "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a")
if [ "$carol_dashboard_a_code" != "403" ]; then
  echo "KO: carol was able to read A's dashboard (code $carol_dashboard_a_code, expected 403)" >&2
  exit 1
fi
echo "OK: carol sees nothing of team A, neither the space nor the dashboard (SP-04 success criterion)"
echo

echo "== Proxy (SP-04): equipe-a-*/equipe-b-* data isolation via run_as =="
alice_data_a=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-a-sample/_search")
alice_data_b=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-b-sample/_search")
carol_data_a=$(curl -s -o /dev/null -w '%{http_code}' -u "carol:${CAROL_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-a-sample/_search")
carol_data_b=$(curl -s -o /dev/null -w '%{http_code}' -u "carol:${CAROL_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-b-sample/_search")
if [ "$alice_data_a" != "200" ] || [ "$alice_data_b" != "403" ] || [ "$carol_data_a" != "403" ] || [ "$carol_data_b" != "200" ]; then
  echo "KO: unexpected data isolation (alice->A=$alice_data_a, alice->B=$alice_data_b, carol->A=$carol_data_a, carol->B=$carol_data_b)" >&2
  exit 1
fi
echo "OK: alice reads equipe-a-sample (200) and not equipe-b-sample (403, run_as + equipe_a_viewer role);"
echo "    carol reads equipe-b-sample (200) and not equipe-a-sample (403, run_as + equipe_b_viewer role)"
echo

echo "All green: Elasticsearch and Kibana accept the native elastic login,"
echo "through a transparent proxy that logs calls (SP-02);"
echo "OpenLDAP contains alice, bob, carol and their team groups, and alice"
echo "logs into Kibana with her LDAP password under her own identity,"
echo "with the equipe_a_viewer role, via the proxy's run_as (SP-03, approach A);"
echo "alice only reads team A's space and data, bob edits a"
echo "team A dashboard, carol sees nothing of team A (SP-04)."
