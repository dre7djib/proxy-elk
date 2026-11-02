#!/usr/bin/env bash
# Phase 1 acceptance check, once over OIDC and once over LDAP:
#   1. login -> /auth/me (subject, method, groups)
#   2. alice reads equipe-a-sample
#   3. alice is denied equipe-b-sample, with an explicit message
#   4. both lines are in the proxy's JSON audit
#   5. LDAP: carol (equipe-b-viewer) reads equipe-b-sample and not equipe-a-sample
#
# Ask and Discover are not in this script: they depend on phase 2.
# Reads go through the session cookie. verify.sh's Basic auth
# does not show up in the audit (identity is read from the cookie).
#
# Usage: from deploy/demo/, after `docker compose up -d`:
#   ./scripts/accept.sh
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

# Timestamp before the requests: docker compose logs --since must not
# mix in a previous run.
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

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

header_value() {
  local name="$1"
  awk -v name="$name" 'BEGIN { IGNORECASE = 1 } $1 == name":" { sub(/\r$/, "", $2); print $2; exit }'
}

echo "== Waiting for services =="
wait_for "Product proxy" curl -sf http://127.0.0.1:8081/health
wait_for "Keycloak" curl -sf http://127.0.0.1:18080/realms/demo
echo "OK: proxy, keycloak respond"
echo

oidc_jar=$(mktemp)
ldap_alice_jar=$(mktemp)
ldap_carol_jar=$(mktemp)
body=$(mktemp)
trap 'rm -f "$oidc_jar" "$ldap_alice_jar" "$ldap_carol_jar" "$body"' EXIT

# Authorization code flow. The Keycloak client has no password grant.
# --resolve avoids an /etc/hosts entry: the demo issuer is
# http://keycloak:18080, the callback stays http://127.0.0.1:8081.
oidc_session() {
  local user="$1"
  local password="$2"
  local jar="$3"
  local headers location page action code

  headers=$(curl -sS -D - -o /dev/null -c "$jar" "http://127.0.0.1:8081/auth/login")
  location=$(printf '%s\n' "$headers" | header_value Location)
  if [ -z "$location" ]; then
    echo "KO: /auth/login did not redirect to Keycloak" >&2
    exit 1
  fi

  page=$(curl -sS -c "$jar" -b "$jar" --resolve keycloak:18080:127.0.0.1 "$location")
  action=$(printf '%s' "$page" | sed -n 's/.*action="\([^"]*\)".*/\1/p' | head -n 1)
  action=${action//&amp;/&}
  if [ -z "$action" ]; then
    echo "KO: Keycloak form not found" >&2
    exit 1
  fi
  case "$action" in
    http://* | https://*) ;;
    /*) action="http://keycloak:18080${action}" ;;
    *)
      echo "KO: unexpected form action: $action" >&2
      exit 1
      ;;
  esac

  headers=$(curl -sS -D - -o "$body" -c "$jar" -b "$jar" --resolve keycloak:18080:127.0.0.1 \
    -X POST \
    --data-urlencode "username=${user}" \
    --data-urlencode "password=${password}" \
    --data-urlencode "credentialId=" \
    "$action")
  code=$(printf '%s\n' "$headers" | awk 'BEGIN { code = "" } /^HTTP\// { code = $2 } END { print code }')
  location=$(printf '%s\n' "$headers" | header_value Location)
  if [ "$code" != "302" ] && [ "$code" != "303" ]; then
    echo "KO: Keycloak login for ${user} returned ${code} (expected a redirect)" >&2
    exit 1
  fi
  case "$location" in
    http://127.0.0.1:8081/auth/callback*) ;;
    *)
      echo "KO: Keycloak did not redirect to /auth/callback: ${location}" >&2
      exit 1
      ;;
  esac

  # The callback sets the session cookie and redirects to /auth/me.
  curl -sS -o "$body" -c "$jar" -b "$jar" -L --max-redirs 3 "$location" >/dev/null
}

expect_me() {
  local jar="$1"
  local user="$2"
  local method="$3"
  local group="$4"
  local me
  me=$(curl -sS -b "$jar" http://127.0.0.1:8081/auth/me)
  if ! printf '%s' "$me" | grep -q "\"subject\":\"${user}\""; then
    echo "KO: /auth/me does not return ${user}: ${me}" >&2
    exit 1
  fi
  if ! printf '%s' "$me" | grep -q "\"method\":\"${method}\""; then
    echo "KO: /auth/me is missing method ${method}: ${me}" >&2
    exit 1
  fi
  if ! printf '%s' "$me" | grep -q "${group}"; then
    echo "KO: /auth/me is missing group ${group}: ${me}" >&2
    exit 1
  fi
}

expect_index() {
  local jar="$1"
  local index="$2"
  local want="$3"
  local code
  code=$(curl -sS -o "$body" -w '%{http_code}' -b "$jar" "http://127.0.0.1:8081/${index}/_count")
  if [ "$code" != "$want" ]; then
    echo "KO: ${index} returned ${code} (expected ${want}): $(cat "$body")" >&2
    exit 1
  fi
  if [ "$want" = "403" ]; then
    if ! grep -q "access denied to index ${index}" "$body"; then
      echo "KO: denial of ${index} has no explicit message: $(cat "$body")" >&2
      exit 1
    fi
  fi
}

echo "== 1. OIDC: alice login (code flow) =="
oidc_session alice "${ALICE_PASSWORD}" "$oidc_jar"
expect_me "$oidc_jar" alice oidc equipe-a-viewer
echo "OK: alice authenticated over OIDC, group equipe-a-viewer"
echo

echo "== 2. OIDC: allowed index, denied index =="
expect_index "$oidc_jar" equipe-a-sample 200
expect_index "$oidc_jar" equipe-b-sample 403
echo "OK: alice reads equipe-a-sample, equipe-b-sample denied"
echo

echo "== 3. LDAP: alice login =="
ldap_code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$ldap_alice_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}")
if [ "$ldap_code" != "302" ]; then
  echo "KO: LDAPS login alice returned ${ldap_code} (expected 302)" >&2
  exit 1
fi
expect_me "$ldap_alice_jar" alice ldap equipe-a-viewer
echo "OK: alice authenticated over LDAPS, group equipe-a-viewer"
echo

echo "== 4. LDAP: allowed index, denied index =="
expect_index "$ldap_alice_jar" equipe-a-sample 200
expect_index "$ldap_alice_jar" equipe-b-sample 403
echo "OK: alice reads equipe-a-sample, equipe-b-sample denied"
echo

echo "== 5. LDAP: groups decide (carol, equipe-b-viewer) =="
carol_code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$ldap_carol_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"carol\",\"password\":\"${CAROL_PASSWORD}\"}")
if [ "$carol_code" != "302" ]; then
  echo "KO: LDAPS login carol returned ${carol_code} (expected 302)" >&2
  exit 1
fi
expect_me "$ldap_carol_jar" carol ldap equipe-b-viewer
expect_index "$ldap_carol_jar" equipe-b-sample 200
expect_index "$ldap_carol_jar" equipe-a-sample 403
echo "OK: carol reads equipe-b-sample, equipe-a-sample denied"
echo

echo "== 6. Audit: allowed and denied, OIDC then LDAP =="
require_audit() {
  local method="$1"
  local index="$2"
  local decision="$3"
  local tries=10
  local logf
  logf=$(mktemp)
  while [ "$tries" -gt 0 ]; do
    docker compose logs --since "$since" proxy >"$logf" 2>&1 || true
    if grep -E "\"user\":\"alice\",\"method\":\"${method}\",\"decision\":\"${decision}\".*${index}" "$logf" >/dev/null; then
      rm -f "$logf"
      return 0
    fi
    tries=$((tries - 1))
    sleep 1
  done
  echo "KO: missing audit line (alice ${method} ${index} ${decision})" >&2
  tail -n 40 "$logf" >&2 || true
  rm -f "$logf"
  exit 1
}
require_audit oidc equipe-a-sample allowed
require_audit oidc equipe-b-sample denied
require_audit ldap equipe-a-sample allowed
require_audit ldap equipe-b-sample denied
echo "OK: the four lines are in the audit"
echo

echo "OK: phase 1 scenario (OIDC then LDAP)"
