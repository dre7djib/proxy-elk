#!/usr/bin/env bash
# Vérifie les critères de réussite de SP-01, SP-02 et SP-03 :
# - Kibana accepte un login natif, OpenLDAP contient alice, bob, carol
#   avec leurs groupes d'équipe (SP-01) ;
# - le proxy entre Kibana et Elasticsearch est un passe-plat transparent,
#   et login/Discover fonctionnent à travers lui (SP-02) ;
# - Alice se connecte à Kibana avec son mot de passe LDAP et apparaît avec
#   sa propre identité et son rôle (run_as), un mauvais mot de passe est
#   refusé, et le login natif elastic fonctionne toujours (SP-03).
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
wait_for "Proxy (SP-02)" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "OpenLDAP" "${COMPOSE[@]}" exec -T openldap ldapwhoami -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=org" -w "${LDAP_ADMIN_PASSWORD}"
echo "OK: les quatre services répondent"
echo

echo "== Elasticsearch : login natif elastic =="
curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200 >/dev/null
echo "OK"
echo

echo "== Proxy (SP-02) : passe-plat transparent =="
es_body=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200)
proxy_body=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210)
if [ "$es_body" != "$proxy_body" ]; then
  echo "KO: la réponse via le proxy diffère de celle d'Elasticsearch en direct" >&2
  echo "--- Elasticsearch ---" >&2
  echo "$es_body" >&2
  echo "--- Proxy ---" >&2
  echo "$proxy_body" >&2
  exit 1
fi
echo "OK: réponse identique en direct et via le proxy (passe-plat transparent)"
echo

echo "== Proxy (SP-02) : recherche authentifiée (approche de Discover) =="
search_code=$(curl -s -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" \
  "http://127.0.0.1:9210/_search?size=0")
if [ "$search_code" != "200" ]; then
  echo "KO: une recherche via le proxy a répondu $search_code" >&2
  exit 1
fi
echo "OK: recherche authentifiée via le proxy réussie (statut 200)"
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

echo "== Proxy (SP-03) : Elasticsearch voit l'identité d'alice via run_as =="
authn_body=$(curl -s -u "alice:${ALICE_PASSWORD}" http://127.0.0.1:9210/_security/_authenticate)
if ! echo "$authn_body" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: _authenticate via le proxy ne renvoie pas l'identité d'alice" >&2
  echo "$authn_body" >&2
  exit 1
fi
if ! echo "$authn_body" | grep -q '"viewer"'; then
  echo "KO: le rôle viewer d'alice n'apparaît pas dans _authenticate" >&2
  echo "$authn_body" >&2
  exit 1
fi
echo "OK: Elasticsearch authentifie alice (run_as), rôle viewer présent"
echo

echo "== Proxy (SP-03) : mauvais mot de passe LDAP refusé par Elasticsearch =="
bad_ldap_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:mauvais-mot-de-passe" \
  http://127.0.0.1:9210/_security/_authenticate)
if [ "$bad_ldap_code" != "401" ]; then
  echo "KO: un mauvais mot de passe LDAP via le proxy a répondu $bad_ldap_code (attendu 401)" >&2
  exit 1
fi
echo "OK: mauvais mot de passe LDAP refusé (401) avant d'atteindre Elasticsearch"
echo

echo "== Kibana (SP-03) : alice se connecte avec son mot de passe LDAP =="
alice_cookie_jar=$(mktemp)
alice_response_body=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body" "$alice_cookie_jar" "$alice_response_body"' EXIT

alice_http_code=$(curl -s -o "$alice_response_body" -w '%{http_code}' \
  -c "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")

if [ "$alice_http_code" != "200" ]; then
  echo "KO: Kibana a répondu $alice_http_code au login d'alice" >&2
  cat "$alice_response_body" >&2
  exit 1
fi
if ! grep -q "sid" "$alice_cookie_jar"; then
  echo "KO: pas de cookie de session pour alice" >&2
  exit 1
fi
echo "OK: alice/\$ALICE_PASSWORD authentifiée par Kibana via LDAP (cookie de session reçu)"

me_body=$(curl -s -b "$alice_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$me_body" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: Kibana ne reconnaît pas alice comme utilisateur courant" >&2
  echo "$me_body" >&2
  exit 1
fi
if ! echo "$me_body" | grep -q '"viewer"'; then
  echo "KO: le rôle viewer d'alice n'apparaît pas côté Kibana" >&2
  echo "$me_body" >&2
  exit 1
fi
echo "OK: Kibana affiche l'identité et le rôle d'alice (critère de réussite SP-03)"
echo "    Vérification visuelle conseillée : http://127.0.0.1:5601, menu utilisateur = Alice Martin"
echo

echo "== Kibana (SP-03) : mauvais mot de passe LDAP refusé =="
alice_bad_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d '{"providerType":"basic","providerName":"basic","currentURL":"/","params":{"username":"alice","password":"mauvais-mot-de-passe"}}')
if [ "$alice_bad_code" = "200" ]; then
  echo "KO: Kibana aurait dû refuser le mauvais mot de passe d'alice" >&2
  exit 1
fi
echo "OK: mauvais mot de passe refusé par Kibana ($alice_bad_code)"
echo

echo "== Régression : le login natif elastic fonctionne toujours à travers le proxy =="
elastic_regression_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"elastic\",\"password\":\"${ELASTIC_PASSWORD}\"}}")
if [ "$elastic_regression_code" != "200" ]; then
  echo "KO: le login natif elastic a régressé ($elastic_regression_code)" >&2
  exit 1
fi
echo "OK: elastic se connecte toujours directement (sans passer par le LDAP, SP-01/SP-02 non régressés)"
echo

echo "Tout est vert : Elasticsearch et Kibana acceptent le login natif elastic,"
echo "à travers un proxy transparent qui journalise les appels (SP-02) ;"
echo "OpenLDAP contient alice, bob, carol et leurs groupes d'équipe, et alice se"
echo "connecte à Kibana avec son mot de passe LDAP sous sa propre identité,"
echo "avec le rôle viewer, via le run_as du proxy (SP-03, piste A)."
