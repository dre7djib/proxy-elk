#!/usr/bin/env bash
# Vérifie les critères de réussite de SP-01 à SP-04 :
# - Kibana accepte un login natif, OpenLDAP contient alice, bob, carol
#   avec leurs groupes d'équipe (SP-01) ;
# - le proxy entre Kibana et Elasticsearch est un passe-plat transparent,
#   et login/Discover fonctionnent à travers lui (SP-02) ;
# - Alice se connecte à Kibana avec son mot de passe LDAP et apparaît avec
#   sa propre identité et son rôle (run_as), un mauvais mot de passe est
#   refusé, et le login natif elastic fonctionne toujours (SP-03) ;
# - Rôles ES et spaces Kibana par équipe (SP-04) : alice (equipe_a_viewer)
#   ne voit que le space equipe-a en lecture et les données equipe-a-*, bob
#   (equipe_a_editor) peut modifier un dashboard du space equipe-a, carol
#   (equipe_b_viewer) ne voit ni le space equipe-a ni ses données.
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

echo "== Proxy (SP-03/SP-04) : Elasticsearch voit l'identité d'alice via run_as =="
authn_body=$(curl -s -u "alice:${ALICE_PASSWORD}" http://127.0.0.1:9210/_security/_authenticate)
if ! echo "$authn_body" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: _authenticate via le proxy ne renvoie pas l'identité d'alice" >&2
  echo "$authn_body" >&2
  exit 1
fi
if ! echo "$authn_body" | grep -q '"equipe_a_viewer"'; then
  echo "KO: le rôle equipe_a_viewer d'alice n'apparaît pas dans _authenticate" >&2
  echo "$authn_body" >&2
  exit 1
fi
echo "OK: Elasticsearch authentifie alice (run_as), rôle equipe_a_viewer présent (SP-04)"
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
if ! echo "$me_body" | grep -q '"equipe_a_viewer"'; then
  echo "KO: le rôle equipe_a_viewer d'alice n'apparaît pas côté Kibana" >&2
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

echo "== Attente du service kibana-setup (SP-04) =="
kibana_setup_tries=30
until "${COMPOSE[@]}" ps -a kibana-setup --format '{{.State}}' 2>/dev/null | grep -q '^exited$'; do
  kibana_setup_tries=$((kibana_setup_tries - 1))
  if [ "$kibana_setup_tries" -le 0 ]; then
    echo "KO: kibana-setup n'a pas terminé à temps" >&2
    exit 1
  fi
  sleep 2
done
kibana_setup_exit=$("${COMPOSE[@]}" ps -a kibana-setup --format '{{.ExitCode}}')
if [ "$kibana_setup_exit" != "0" ]; then
  echo "KO: kibana-setup a échoué (code $kibana_setup_exit) : voir 'docker compose logs kibana-setup'" >&2
  exit 1
fi
echo "OK: kibana-setup terminé avec succès (spaces equipe-a/equipe-b et rôles prêts)"
echo

echo "== Kibana (SP-04) : bob (équipe A, editor) se connecte =="
bob_cookie_jar=$(mktemp)
carol_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$response_body" "$alice_cookie_jar" "$alice_response_body" "$bob_cookie_jar" "$carol_cookie_jar"' EXIT
bob_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$bob_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"bob\",\"password\":\"${BOB_PASSWORD}\"}}")
if [ "$bob_http_code" != "200" ]; then
  echo "KO: Kibana a répondu $bob_http_code au login de bob" >&2
  exit 1
fi
echo "OK: bob authentifié par Kibana"
echo

echo "== Kibana (SP-04) : carol (équipe B, viewer) se connecte =="
carol_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$carol_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"carol\",\"password\":\"${CAROL_PASSWORD}\"}}")
if [ "$carol_http_code" != "200" ]; then
  echo "KO: Kibana a répondu $carol_http_code au login de carol" >&2
  exit 1
fi
echo "OK: carol authentifiée par Kibana"
echo

echo "== Kibana (SP-04) : alice voit uniquement le space equipe-a =="
alice_spaces=$(curl -s -b "$alice_cookie_jar" http://127.0.0.1:5601/api/spaces/space)
if ! echo "$alice_spaces" | grep -q '"id":"equipe-a"'; then
  echo "KO: alice ne voit pas le space equipe-a" >&2
  echo "$alice_spaces" >&2
  exit 1
fi
if echo "$alice_spaces" | grep -q '"id":"equipe-b"'; then
  echo "KO: alice voit le space equipe-b, qui devrait lui être invisible" >&2
  echo "$alice_spaces" >&2
  exit 1
fi
echo "OK: alice ne voit que le space equipe-a"
echo

echo "== Kibana (SP-04) : alice lit le dashboard du space equipe-a =="
alice_dashboard_get=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a")
if [ "$alice_dashboard_get" != "200" ]; then
  echo "KO: alice n'a pas pu lire le dashboard de l'équipe A (code $alice_dashboard_get)" >&2
  exit 1
fi
echo "OK: alice lit le dashboard de l'équipe A"
echo

echo "== Kibana (SP-04) : alice (viewer) ne peut PAS modifier le dashboard de A =="
alice_dashboard_put=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a" \
  -d '{"attributes":{"title":"Essai en lecture seule (devrait echouer)"}}')
if [ "$alice_dashboard_put" != "403" ]; then
  echo "KO: alice (viewer) a pu modifier le dashboard de A (code $alice_dashboard_put, attendu 403)" >&2
  exit 1
fi
echo "OK: alice (viewer) ne peut pas modifier le dashboard de A (403)"
echo

echo "== Kibana (SP-04) : alice (base read) n'a pas accès à Dev Tools =="
alice_devtools_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$alice_cookie_jar" \
  -H 'kbn-xsrf: true' \
  -X POST "http://127.0.0.1:5601/api/console/proxy?path=_search&method=GET")
if [ "$alice_devtools_code" != "403" ]; then
  echo "KO: alice (viewer, base read) a accédé à Dev Tools (code $alice_devtools_code, attendu 403)" >&2
  exit 1
fi
echo "OK: Dev Tools refusé à alice par le seul base:read (constat F75 : pas besoin de feature privileges custom)"
echo

echo "== Kibana (SP-04) : bob (editor) peut modifier le dashboard de A =="
bob_dashboard_put=$(curl -s -o /dev/null -w '%{http_code}' -b "$bob_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X PUT "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a" \
  -d '{"attributes":{"title":"Dashboard equipe A modifie par bob (verify.sh)"}}')
if [ "$bob_dashboard_put" != "200" ]; then
  echo "KO: bob (editor) n'a pas pu modifier le dashboard de A (code $bob_dashboard_put)" >&2
  exit 1
fi
echo "OK: bob (editor) modifie le dashboard de A (critère de réussite SP-04)"
echo

echo "== Kibana (SP-04) : carol ne voit que le space equipe-b, pas equipe-a =="
carol_spaces=$(curl -s -b "$carol_cookie_jar" http://127.0.0.1:5601/api/spaces/space)
if echo "$carol_spaces" | grep -q '"id":"equipe-a"'; then
  echo "KO: carol voit le space equipe-a, qui devrait lui être invisible" >&2
  echo "$carol_spaces" >&2
  exit 1
fi
if ! echo "$carol_spaces" | grep -q '"id":"equipe-b"'; then
  echo "KO: carol ne voit pas son propre space equipe-b" >&2
  echo "$carol_spaces" >&2
  exit 1
fi
echo "OK: carol ne voit que le space equipe-b"
echo

echo "== Kibana (SP-04) : carol n'a aucun accès direct au space ni au dashboard de A =="
carol_space_a_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$carol_cookie_jar" \
  "http://127.0.0.1:5601/api/spaces/space/equipe-a")
if [ "$carol_space_a_code" != "403" ]; then
  echo "KO: carol a pu accéder au space equipe-a (code $carol_space_a_code, attendu 403)" >&2
  exit 1
fi
carol_dashboard_a_code=$(curl -s -o /dev/null -w '%{http_code}' -b "$carol_cookie_jar" \
  "http://127.0.0.1:5601/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a")
if [ "$carol_dashboard_a_code" != "403" ]; then
  echo "KO: carol a pu lire le dashboard de A (code $carol_dashboard_a_code, attendu 403)" >&2
  exit 1
fi
echo "OK: carol ne voit rien de l'équipe A, ni le space ni le dashboard (critère de réussite SP-04)"
echo

echo "== Proxy (SP-04) : isolation des données equipe-a-*/equipe-b-* via run_as =="
alice_data_a=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-a-sample/_search")
alice_data_b=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-b-sample/_search")
carol_data_a=$(curl -s -o /dev/null -w '%{http_code}' -u "carol:${CAROL_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-a-sample/_search")
carol_data_b=$(curl -s -o /dev/null -w '%{http_code}' -u "carol:${CAROL_PASSWORD}" \
  "http://127.0.0.1:9210/equipe-b-sample/_search")
if [ "$alice_data_a" != "200" ] || [ "$alice_data_b" != "403" ] || [ "$carol_data_a" != "403" ] || [ "$carol_data_b" != "200" ]; then
  echo "KO: isolation des données inattendue (alice->A=$alice_data_a, alice->B=$alice_data_b, carol->A=$carol_data_a, carol->B=$carol_data_b)" >&2
  exit 1
fi
echo "OK: alice lit equipe-a-sample (200) et pas equipe-b-sample (403, run_as + rôle equipe_a_viewer) ;"
echo "    carol lit equipe-b-sample (200) et pas equipe-a-sample (403, run_as + rôle equipe_b_viewer)"
echo

echo "Tout est vert : Elasticsearch et Kibana acceptent le login natif elastic,"
echo "à travers un proxy transparent qui journalise les appels (SP-02) ;"
echo "OpenLDAP contient alice, bob, carol et leurs groupes d'équipe, et alice se"
echo "connecte à Kibana avec son mot de passe LDAP sous sa propre identité,"
echo "avec le rôle equipe_a_viewer, via le run_as du proxy (SP-03, piste A) ;"
echo "alice lit seulement le space et les données de l'équipe A, bob modifie un"
echo "dashboard de l'équipe A, carol ne voit rien de l'équipe A (SP-04)."
