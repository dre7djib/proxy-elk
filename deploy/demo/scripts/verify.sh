#!/usr/bin/env bash
# Vérifie le critère F68 (one-command demo) de J1-13 :
#   1. proxy produit : /health, /metrics
#   2. proxy produit : login LDAPS -> /auth/me
#   3. proxy produit : smoke OIDC (redirect 302 vers Keycloak)
#   4. gateway (spike Track A) : login Kibana alice (réutilise les
#      assertions de spike/scripts/verify.sh)
#   5. indices seedés présents
#
# Usage : depuis deploy/demo/, après `docker compose up -d` :
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
wait_for "Elasticsearch" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200
wait_for "Gateway (Track A)" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "Product proxy" curl -sf http://127.0.0.1:8081/health
wait_for "Keycloak" curl -sf http://127.0.0.1:18080/realms/demo
echo "OK: elasticsearch, gateway, kibana, proxy, keycloak respond"
echo

echo "== 1. Proxy produit : /health et /metrics =="
curl -sf http://127.0.0.1:8081/health >/dev/null
curl -sf http://127.0.0.1:8081/metrics | grep -q .
echo "OK"
echo

echo "== 2. Proxy produit : login LDAPS alice -> /auth/me =="
cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar"' EXIT
login_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$cookie_jar" \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d "{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}")
if [ "$login_code" != "302" ]; then
  echo "KO: login LDAPS alice via le proxy produit a renvoyé $login_code (attendu 302)" >&2
  exit 1
fi
me_body=$(curl -s -b "$cookie_jar" http://127.0.0.1:8081/auth/me)
if ! echo "$me_body" | grep -q '"alice"'; then
  echo "KO: /auth/me ne renvoie pas l'identité alice : $me_body" >&2
  exit 1
fi
echo "OK: alice authentifiée en LDAPS par le proxy produit (F5)"
echo

echo "== 2bis. Proxy produit : mauvais mot de passe refusé =="
bad_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:8081/auth/ldap" \
  -d '{"username":"alice","password":"wrong"}')
if [ "$bad_code" != "401" ]; then
  echo "KO: mauvais mot de passe renvoie $bad_code (attendu 401)" >&2
  exit 1
fi
echo "OK"
echo

echo "== 3. Proxy produit : smoke OIDC (redirect vers Keycloak) =="
oidc_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/auth/login")
if [ "$oidc_code" != "302" ] && [ "$oidc_code" != "303" ]; then
  echo "KO: /auth/login a renvoyé $oidc_code (attendu redirect vers Keycloak)" >&2
  exit 1
fi
echo "OK: /auth/login redirige (code $oidc_code)"
echo

echo "== 4. Gateway (Track A) : login Kibana alice (LDAP), cf. spike/scripts/verify.sh =="
kbn_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$kbn_cookie_jar"' EXIT
kbn_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$kbn_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$kbn_http_code" != "200" ]; then
  echo "KO: Kibana a renvoyé $kbn_http_code pour le login d'alice via le gateway" >&2
  exit 1
fi
kbn_me=$(curl -s -b "$kbn_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$kbn_me" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: Kibana ne reconnaît pas alice comme utilisateur courant" >&2
  exit 1
fi
echo "OK: alice se connecte à Kibana via le gateway (Track A)"
echo

echo "== 5. Indices seedés présents =="
for idx in equipe-a-sample equipe-b-sample; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" \
    "http://127.0.0.1:9200/${idx}/_count")
  if [ "$code" != "200" ]; then
    echo "KO: index ${idx} absent ou inaccessible (code $code)" >&2
    exit 1
  fi
done
echo "OK: equipe-a-sample et equipe-b-sample présents"
echo

echo "All green: démo J1-13 opérationnelle en une commande (F68)."
