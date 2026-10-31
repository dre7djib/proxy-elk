#!/usr/bin/env bash
# Vérifie le critère F68 (one-command demo) de J1-13, et le relais ES
# (run_as, J1-15, F2) :
#   1. proxy produit : /health, /metrics
#   2. proxy produit : login LDAPS -> /auth/me
#   3. proxy produit : smoke OIDC (redirect 302 vers Keycloak)
#   4. Kibana login alice via le proxy produit (seul chemin
#      Kibana -> Elasticsearch de cette démo)
#   5. relais ES : alice lit equipe-a-sample via le proxy, equipe-b-sample
#      lui est refusé (ACL, configs/proxy.yaml)
#   6. SSO Kerberos/SPNEGO : 401+Negotiate sans ticket, puis alice avec
#      un vrai ticket (kinit depuis le conteneur krb5-user) jusqu'au
#      relais ES
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
wait_for "Kibana" curl -sf http://127.0.0.1:5601/api/status
wait_for "Product proxy" curl -sf http://127.0.0.1:8081/health
wait_for "Keycloak" curl -sf http://127.0.0.1:18080/realms/demo
echo "OK: kibana, proxy, keycloak respond"
echo

echo "== 0. Elasticsearch injoignable en direct (F66, F69) =="
if curl -s -o /dev/null -m 3 http://127.0.0.1:9200; then
  echo "KO: 127.0.0.1:9200 a répondu, elasticsearch ne devrait pas être exposé sur l'hôte" >&2
  exit 1
fi
echo "OK: 127.0.0.1:9200 refuse la connexion (réseau es interne)"
echo

echo "== 1. Proxy produit : /health et /metrics =="
curl -sf http://127.0.0.1:8081/health >/dev/null
metrics_body=$(curl -sf http://127.0.0.1:8081/metrics)
echo "$metrics_body" | grep -q .
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

echo "== 4. Login Kibana alice (LDAP) via le proxy produit (J1-15) =="
kbn_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$kbn_cookie_jar"' EXIT
kbn_http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -c "$kbn_cookie_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$kbn_http_code" != "200" ]; then
  echo "KO: Kibana a renvoyé $kbn_http_code pour le login d'alice via le proxy produit" >&2
  exit 1
fi
kbn_me=$(curl -s -b "$kbn_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$kbn_me" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: Kibana ne reconnaît pas alice comme utilisateur courant" >&2
  exit 1
fi
echo "OK: alice se connecte à Kibana via le proxy produit (seul chemin vers Elasticsearch)"
echo

echo "== 4bis. SSO Kibana (/auth/kibana) : login unique, jamais le formulaire Kibana =="
sso_cookie_jar=$(mktemp)
trap 'rm -f "$cookie_jar" "$kbn_cookie_jar" "$sso_cookie_jar"' EXIT
sso_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$sso_cookie_jar" \
  -X POST "http://127.0.0.1:8081/auth/kibana" \
  -d "username=alice&password=${ALICE_PASSWORD}")
if [ "$sso_code" != "302" ]; then
  echo "KO: /auth/kibana a renvoyé $sso_code (attendu 302)" >&2
  exit 1
fi
sso_me=$(curl -s -b "$sso_cookie_jar" http://127.0.0.1:5601/internal/security/me)
if ! echo "$sso_me" | grep -qE '"username"[[:space:]]*:[[:space:]]*"alice"'; then
  echo "KO: le cookie Kibana posé par /auth/kibana ne reconnaît pas alice : $sso_me" >&2
  exit 1
fi
echo "OK: un seul login côté proxy connecte alice à Kibana, sans son formulaire"
echo

echo "== 5. Relais ES (run_as, J1-15) : ACL appliquée via le proxy produit =="
alice_a_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:8081/equipe-a-sample/_count")
if [ "$alice_a_code" != "200" ]; then
  echo "KO: alice ne peut pas lire equipe-a-sample via le proxy (code $alice_a_code)" >&2
  exit 1
fi
alice_b_code=$(curl -s -o /dev/null -w '%{http_code}' -u "alice:${ALICE_PASSWORD}" \
  "http://127.0.0.1:8081/equipe-b-sample/_count")
if [ "$alice_b_code" != "403" ]; then
  echo "KO: alice a pu lire equipe-b-sample via le proxy (code $alice_b_code, attendu 403)" >&2
  exit 1
fi
echo "OK: alice lit equipe-a-sample (run_as), equipe-b-sample lui est refusé (ACL)"
echo

echo "== 6. SSO Kerberos/SPNEGO (/auth/kibana) : challenge sans ticket =="
negotiate_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/auth/kibana")
negotiate_header=$(curl -s -o /dev/null -D - "http://127.0.0.1:8081/auth/kibana" | grep -i '^www-authenticate:' || true)
if [ "$negotiate_code" != "401" ]; then
  echo "KO: GET /auth/kibana sans ticket a renvoyé $negotiate_code (attendu 401)" >&2
  exit 1
fi
if ! echo "$negotiate_header" | grep -qi 'Negotiate'; then
  echo "KO: WWW-Authenticate: Negotiate absent de la réponse 401 : $negotiate_header" >&2
  exit 1
fi
echo "OK: 401 + WWW-Authenticate: Negotiate sans ticket"
echo

echo "== 6bis. SSO Kerberos/SPNEGO : alice avec un vrai ticket (krb5-user) =="
docker compose exec -T krb5-user bash -c "echo '${ALICE_PASSWORD}' | kinit alice" >/dev/null
krb_sso_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/auth/kibana")
if [ "$krb_sso_code" != "302" ]; then
  echo "KO: GET /auth/kibana avec ticket alice a renvoyé $krb_sso_code (attendu 302)" >&2
  exit 1
fi
krb_count_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/equipe-a-sample/_count")
if [ "$krb_count_code" != "200" ]; then
  echo "KO: relais ES via Negotiate (alice, equipe-a-sample) a renvoyé $krb_count_code (attendu 200)" >&2
  exit 1
fi
krb_denied_code=$(docker compose exec -T krb5-user curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://proxy:8080/equipe-b-sample/_count")
if [ "$krb_denied_code" != "403" ]; then
  echo "KO: relais ES via Negotiate (alice, equipe-b-sample) a renvoyé $krb_denied_code (attendu 403)" >&2
  exit 1
fi
echo "OK: alice s'authentifie via Kerberos (ticket réel), ACL appliquée au relais ES"
echo

echo "All green: démo J1-13/J1-15 opérationnelle en une commande (F68, F2)."
