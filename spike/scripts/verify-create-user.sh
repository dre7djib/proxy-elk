#!/usr/bin/env bash
# Checks Spike Users: create an ES shadow user via the Kibana plugin for
# someone who already exists in LDAP (dave), extend proxy_runas, refuse
# alice, then confirm dave can authenticate through the proxy (run_as).
#
# Usage: from spike/, after `docker compose up -d` (rebuild kibana if the
# plugin changed) and a fresh LDAP volume if dave was just added to the LDIF:
#   ./scripts/verify-create-user.sh
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

DAVE_PASSWORD="${DAVE_PASSWORD:-davepass}"
KIBANA=http://127.0.0.1:5601
PROXY=http://127.0.0.1:9210
ES_DIRECT=http://127.0.0.1:9200
COMPOSE=(docker compose -f docker-compose.yml)

echo "== dave exists in LDAP (bind) but may lack a native ES user =="
if ! "${COMPOSE[@]}" exec -T openldap \
  ldapwhoami -x -H ldap://localhost -D "uid=dave,ou=people,dc=example,dc=org" \
  -w "${DAVE_PASSWORD}" >/dev/null 2>&1; then
  echo "KO: dave missing from LDAP (docker compose down -v && up if LDIF was updated)" >&2
  exit 1
fi
dave_es_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -u "elastic:${ELASTIC_PASSWORD}" "${ES_DIRECT}/_security/user/dave")
if [ "$dave_es_code" = "200" ]; then
  echo "Note: dave already exists in ES (re-run is idempotent); continuing"
else
  echo "OK: no native user dave yet (HTTP $dave_es_code)"
fi
echo

echo "== Plugin route without cookie → 401 (plugin loaded) =="
anon_code=$(curl -s -o /dev/null -w '%{http_code}' -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{"username":"dave","fullName":"Dave Leroy","role":"equipe_a_viewer"}' \
  -X POST "${KIBANA}/api/spike_ask/users")
if [ "$anon_code" != "401" ]; then
  echo "KO: expected 401, got $anon_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== alice (viewer) → POST /api/spike_ask/users → 403 =="
alice_jar=$(mktemp)
elastic_jar=$(mktemp)
trap 'rm -f "$alice_jar" "$elastic_jar" /tmp/spike-alice-create.json' EXIT
alice_login=$(curl -s -o /dev/null -w '%{http_code}' -c "$alice_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "${KIBANA}/internal/security/login" \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$alice_login" != "200" ]; then
  echo "KO: alice Kibana login failed ($alice_login)" >&2
  exit 1
fi
alice_create_code=$(curl -s -o /tmp/spike-alice-create.json -w '%{http_code}' -b "$alice_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"username":"dave","fullName":"Dave Leroy","role":"equipe_a_viewer"}' \
  -X POST "${KIBANA}/api/spike_ask/users")
if [ "$alice_create_code" != "403" ]; then
  echo "KO: expected 403 for alice, got $alice_create_code" >&2
  cat /tmp/spike-alice-create.json >&2 || true
  exit 1
fi
echo "OK"
echo

echo "== elastic → POST /api/spike_ask/users (dave) → 200 =="
elastic_login=$(curl -s -o /dev/null -w '%{http_code}' -c "$elastic_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "${KIBANA}/internal/security/login" \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"elastic\",\"password\":\"${ELASTIC_PASSWORD}\"}}")
if [ "$elastic_login" != "200" ]; then
  echo "KO: elastic Kibana login failed ($elastic_login)" >&2
  exit 1
fi
create_body=$(curl -s -b "$elastic_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"username":"dave","fullName":"Dave Leroy","role":"equipe_a_viewer"}' \
  -X POST "${KIBANA}/api/spike_ask/users")
if ! echo "$create_body" | grep -q '"username":"dave"'; then
  echo "KO: create response missing dave" >&2
  echo "$create_body" >&2
  exit 1
fi
if echo "$create_body" | grep -qi 'password\|NativeShadow\|shadow'; then
  echo "KO: response leaked a password/shadow secret" >&2
  echo "$create_body" >&2
  exit 1
fi
if ! echo "$create_body" | grep -q 'dave'; then
  echo "KO: run_as list should include dave" >&2
  echo "$create_body" >&2
  exit 1
fi
echo "OK: $create_body"
echo

echo "== proxy_runas includes dave =="
role_body=$(curl -sf -u "elastic:${ELASTIC_PASSWORD}" "${ES_DIRECT}/_security/role/proxy_runas")
if ! echo "$role_body" | grep -q '"dave"'; then
  echo "KO: proxy_runas.run_as missing dave" >&2
  echo "$role_body" >&2
  exit 1
fi
echo "OK"
echo

echo "== dave LDAP via proxy → run_as authenticate =="
auth_body=$(curl -sf -u "dave:${DAVE_PASSWORD}" "${PROXY}/_security/_authenticate")
if ! echo "$auth_body" | grep -q '"username":"dave"'; then
  echo "KO: proxy did not authenticate dave as himself" >&2
  echo "$auth_body" >&2
  exit 1
fi
if ! echo "$auth_body" | grep -q 'equipe_a_viewer'; then
  echo "KO: dave missing equipe_a_viewer role" >&2
  echo "$auth_body" >&2
  exit 1
fi
echo "OK: $auth_body"
echo

echo "== Spike Users success criterion met =="
echo "    LDAP-only dave → plugin creates ES shadow user + proxy_runas → run_as works."
