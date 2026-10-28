#!/usr/bin/env bash
# Vérifie le critère de réussite de SP-01 : Kibana accepte un login natif,
# et OpenLDAP contient alice, bob, carol avec leurs groupes d'équipe.
#
# Usage : depuis spike/, après `docker compose up -d` :
#   ./scripts/verify.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Fichier .env manquant. Lancer : cp .env.example .env" >&2
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
      echo "KO: délai dépassé en attendant $description" >&2
      return 1
    fi
    sleep 2
  done
}

echo "== Attente des services =="
wait_for "Elasticsearch" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "OpenLDAP" "${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" -w "${LDAP_ADMIN_PASSWORD}"
echo "OK: les trois services répondent"
echo

echo "== Elasticsearch : login natif elastic =="
curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200 >/dev/null
echo "OK"
echo

echo "== Kibana : login natif elastic via l'API interne =="
cookie_jar=$(mktemp)
response_body=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body"' EXIT

http_code=$(curl -s -o "$response_body" -w '%{http_code}' \
  -c "$cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"elastic\",\"password\":\"${ELASTIC_PASSWORD}\"}}")

if [ "$http_code" != "200" ]; then
  echo "KO: Kibana a répondu $http_code à /internal/security/login" >&2
  cat "$response_body" >&2
  exit 1
fi
if ! grep -q "sid" "$cookie_jar"; then
  echo "KO: pas de cookie de session dans la réponse de Kibana" >&2
  exit 1
fi
echo "OK: elastic/\$ELASTIC_PASSWORD authentifié par Kibana (cookie de session reçu)"
echo "    Vérification visuelle conseillée : http://127.0.0.1:5601"
echo

echo "== OpenLDAP : utilisateurs de test =="
"${COMPOSE[@]}" exec -T openldap ldapsearch -x -H ldap://localhost:389 \
  -D "cn=readonly,dc=example,dc=org" -w "${LDAP_READONLY_PASSWORD}" \
  -b "ou=people,dc=example,dc=org" "(uid=*)" uid cn 2>/dev/null | grep -E '^(dn|uid|cn): '
echo

echo "== OpenLDAP : groupes d'équipe =="
"${COMPOSE[@]}" exec -T openldap ldapsearch -x -H ldap://localhost:389 \
  -D "cn=readonly,dc=example,dc=org" -w "${LDAP_READONLY_PASSWORD}" \
  -b "ou=groups,dc=example,dc=org" "(objectClass=groupOfNames)" cn member 2>/dev/null | grep -E '^(dn|cn|member): '
echo

echo "== OpenLDAP : bind alice avec son mot de passe LDAP =="
"${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=people,dc=example,dc=org" -w "${ALICE_PASSWORD}" >/dev/null
echo "OK: bind alice réussi"
echo

echo "== OpenLDAP : bind refusé avec un mauvais mot de passe =="
if "${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=alice,ou=people,dc=example,dc=org" -w "mauvais-mot-de-passe" >/dev/null 2>&1; then
  echo "KO: le bind aurait dû être refusé" >&2
  exit 1
fi
echo "OK: bind refusé comme attendu"
echo

echo "Tout est vert : Elasticsearch et Kibana acceptent le login natif elastic ;"
echo "OpenLDAP contient alice, bob, carol et leurs groupes d'équipe."
echo "Rappel : OpenLDAP n'est pas encore branché à Kibana (voir SP-03)."
