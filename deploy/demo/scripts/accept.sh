#!/usr/bin/env bash
# Critère d'acceptation J1 (TR-03), une fois en OIDC et une fois en LDAP :
#   1. login -> /auth/me (sujet, méthode, groupes)
#   2. alice lit equipe-a-sample
#   3. alice se voit refuser equipe-b-sample, message explicite
#   4. les deux lignes sont dans l'audit JSON du proxy
#   5. LDAP : carol (equipe-b-viewer) lit equipe-b-sample et pas equipe-a-sample
#
# Ask et Discover ne sont pas dans ce script : ils dépendent de J2.
# Les lectures passent par le cookie de session. Le Basic auth de
# verify.sh n'apparaît pas dans l'audit (identité lue sur le cookie).
#
# Usage : depuis deploy/demo/, après `docker compose up -d` :
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

# Horodatage avant les requêtes : docker compose logs --since ne doit
# pas mélanger un passage précédent.
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

# Code flow. Le client Keycloak n'a pas le grant mot de passe.
# --resolve évite une entrée /etc/hosts : l'issuer de la démo est
# http://keycloak:18080, le callback reste http://127.0.0.1:8081.
oidc_session() {
  local user="$1"
  local password="$2"
  local jar="$3"
  local headers location page action code

  headers=$(curl -sS -D - -o /dev/null -c "$jar" "http://127.0.0.1:8081/auth/login")
  location=$(printf '%s\n' "$headers" | header_value Location)
  if [ -z "$location" ]; then
    echo "KO: /auth/login sans redirection vers Keycloak" >&2
    exit 1
  fi

  page=$(curl -sS -c "$jar" -b "$jar" --resolve keycloak:18080:127.0.0.1 "$location")
  action=$(printf '%s' "$page" | sed -n 's/.*action="\([^"]*\)".*/\1/p' | head -n 1)
  action=${action//&amp;/&}
  if [ -z "$action" ]; then
    echo "KO: formulaire Keycloak introuvable" >&2
    exit 1
  fi
  case "$action" in
    http://* | https://*) ;;
    /*) action="http://keycloak:18080${action}" ;;
    *)
      echo "KO: action du formulaire inattendue : $action" >&2
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
    echo "KO: login Keycloak de ${user} a renvoyé ${code} (attendu redirect)" >&2
    exit 1
  fi
  case "$location" in
    http://127.0.0.1:8081/auth/callback*) ;;
    *)
      echo "KO: Keycloak n'a pas renvoyé vers /auth/callback : ${location}" >&2
      exit 1
      ;;
  esac

  # Le callback pose le cookie de session et redirige vers /auth/me.
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
    echo "KO: /auth/me ne renvoie pas ${user} : ${me}" >&2
    exit 1
  fi
  if ! printf '%s' "$me" | grep -q "\"method\":\"${method}\""; then
    echo "KO: /auth/me méthode ${method} absente : ${me}" >&2
    exit 1
  fi
  if ! printf '%s' "$me" | grep -q "${group}"; then
    echo "KO: /auth/me sans le groupe ${group} : ${me}" >&2
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
    echo "KO: ${index} a renvoyé ${code} (attendu ${want}) : $(cat "$body")" >&2
    exit 1
  fi
  if [ "$want" = "403" ]; then
    if ! grep -q "access denied to index ${index}" "$body"; then
      echo "KO: refus de ${index} sans message explicite : $(cat "$body")" >&2
      exit 1
    fi
  fi
}

echo "== 1. OIDC : login alice (code flow) =="
oidc_session alice "${ALICE_PASSWORD}" "$oidc_jar"
expect_me "$oidc_jar" alice oidc equipe-a-viewer
echo "OK: alice authentifiée en OIDC, groupe equipe-a-viewer"
echo

echo "== 2. OIDC : index autorisé, index interdit =="
expect_index "$oidc_jar" equipe-a-sample 200
expect_index "$oidc_jar" equipe-b-sample 403
echo "OK: alice lit equipe-a-sample, equipe-b-sample refusé"
echo

echo "== 3. LDAP : login alice =="
ldap_code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$ldap_alice_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}")
if [ "$ldap_code" != "302" ]; then
  echo "KO: login LDAPS alice a renvoyé ${ldap_code} (attendu 302)" >&2
  exit 1
fi
expect_me "$ldap_alice_jar" alice ldap equipe-a-viewer
echo "OK: alice authentifiée en LDAPS, groupe equipe-a-viewer"
echo

echo "== 4. LDAP : index autorisé, index interdit =="
expect_index "$ldap_alice_jar" equipe-a-sample 200
expect_index "$ldap_alice_jar" equipe-b-sample 403
echo "OK: alice lit equipe-a-sample, equipe-b-sample refusé"
echo

echo "== 5. LDAP : les groupes décident (carol, equipe-b-viewer) =="
carol_code=$(curl -sS -o /dev/null -w '%{http_code}' -c "$ldap_carol_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"carol\",\"password\":\"${CAROL_PASSWORD}\"}")
if [ "$carol_code" != "302" ]; then
  echo "KO: login LDAPS carol a renvoyé ${carol_code} (attendu 302)" >&2
  exit 1
fi
expect_me "$ldap_carol_jar" carol ldap equipe-b-viewer
expect_index "$ldap_carol_jar" equipe-b-sample 200
expect_index "$ldap_carol_jar" equipe-a-sample 403
echo "OK: carol lit equipe-b-sample, equipe-a-sample refusé"
echo

echo "== 6. Audit : exécutée et bloquée, OIDC puis LDAP =="
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
  echo "KO: audit manquant (alice ${method} ${index} ${decision})" >&2
  tail -n 40 "$logf" >&2 || true
  rm -f "$logf"
  exit 1
}
require_audit oidc equipe-a-sample allowed
require_audit oidc equipe-b-sample denied
require_audit ldap equipe-a-sample allowed
require_audit ldap equipe-b-sample denied
echo "OK: les quatre lignes sont dans l'audit"
echo

echo "OK: scénario J1 (OIDC puis LDAP)"
