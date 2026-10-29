#!/usr/bin/env bash
# Vérifie le critère de réussite de SP-06 (F78-F82) : le plugin Kibana réel
# obtient un jeton court (JWT RS256) via Elasticsearch avec la session
# d'alice, et le moteur factice en vérifie la signature, l'expiration et le
# destinataire.
#
# Mise à jour d'exécution (voir spike/README.md#sp-06-plugin-kibana-minimal--jeton-court-moteur-factice) :
# le plugin Kibana (spike/kibana-plugin/) a fini par être compilé et installé
# dans l'image `kibana` de ce compose, après deux correctifs mineurs du
# Dockerfile et un correctif du proxy (en-tête `X-elastic-product`, requis
# par le client ES officiel que `asCurrentUser.transport.request` utilise
# côté plugin). Ce script teste donc directement la vraie route serveur du
# plugin (`POST /api/spike_ask/ask`), puis vérifie indépendamment avec curl
# les vecteurs négatifs du moteur (jeton expiré/mauvaise aud/mauvaise
# signature), qui ne dépendent pas du plugin.
#
# Usage : depuis spike/, après `docker compose up -d` :
#   ./scripts/verify-sp06.sh
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

echo "== Attente du proxy et du moteur factice =="
wait_for "Proxy" curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9210
wait_for "Moteur factice (engine)" "${COMPOSE[@]}" exec -T proxy curl -sf http://engine:8080/health
echo "OK"
echo

echo "== Anonyme : POST /_spike/identity-token sans en-tête → 401 =="
anon_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9210/_spike/identity-token)
if [ "$anon_code" != "401" ]; then
  echo "KO: attendu 401, reçu $anon_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Compte de service (elastic) : aucun jeton pour un compte technique → 403 =="
svc_code=$(curl -s -o /dev/null -w '%{http_code}' -u "elastic:${ELASTIC_PASSWORD}" -X POST http://127.0.0.1:9210/_spike/identity-token)
if [ "$svc_code" != "403" ]; then
  echo "KO: attendu 403, reçu $svc_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Alice : jeton émis par le proxy (variante jeton-via-Elasticsearch, F78) =="
alice_token_body=$(curl -sf -u "alice:${ALICE_PASSWORD}" -X POST http://127.0.0.1:9210/_spike/identity-token)
alice_token=$(echo "$alice_token_body" | sed -E 's/.*"token":"([^"]+)".*/\1/')
if [ -z "$alice_token" ] || [ "$alice_token" = "$alice_token_body" ]; then
  echo "KO: pas de champ token dans la réponse du proxy" >&2
  echo "$alice_token_body" >&2
  exit 1
fi
echo "OK: jeton reçu (tronqué) : ${alice_token:0:32}..."
echo

echo "== Relais au moteur factice : signature, expiration, destinataire (F79) =="
engine_body=$("${COMPOSE[@]}" exec -T proxy curl -s -X POST \
  -H "Authorization: Bearer ${alice_token}" http://engine:8080/whoami)
if ! echo "$engine_body" | grep -q '"sub":"alice"'; then
  echo "KO: le moteur n'a pas reconnu alice comme sujet du jeton" >&2
  echo "$engine_body" >&2
  exit 1
fi
if ! echo "$engine_body" | grep -q 'equipe-a-viewer'; then
  echo "KO: le groupe equipe-a-viewer d'alice n'apparaît pas dans le jeton vérifié" >&2
  echo "$engine_body" >&2
  exit 1
fi
if ! echo "$engine_body" | grep -q '"aud":"spike-engine"'; then
  echo "KO: le destinataire du jeton n'est pas spike-engine" >&2
  echo "$engine_body" >&2
  exit 1
fi
echo "OK: le moteur vérifie signature + expiration + destinataire et retrouve l'identité d'alice"
echo "    $engine_body"
echo

echo "== Plugin Kibana réel : route sans cookie → 401 (pas 404, le plugin est chargé) =="
plugin_anon_code=$(curl -s -o /dev/null -w '%{http_code}' -H 'kbn-xsrf: true' -X POST http://127.0.0.1:5601/api/spike_ask/ask)
if [ "$plugin_anon_code" != "401" ]; then
  echo "KO: attendu 401 (plugin chargé mais non authentifié), reçu $plugin_anon_code" >&2
  exit 1
fi
echo "OK"
echo

echo "== Plugin Kibana réel : session alice → POST /api/spike_ask/ask → 200 =="
plugin_jar=$(mktemp)
trap 'rm -f "$plugin_jar"' EXIT
plugin_login_code=$(curl -s -o /dev/null -w '%{http_code}' -c "$plugin_jar" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:5601/internal/security/login \
  -d "{\"providerType\":\"basic\",\"providerName\":\"basic\",\"currentURL\":\"/\",\"params\":{\"username\":\"alice\",\"password\":\"${ALICE_PASSWORD}\"}}")
if [ "$plugin_login_code" != "200" ]; then
  echo "KO: login Kibana d'alice a échoué ($plugin_login_code)" >&2
  exit 1
fi
plugin_body=$(curl -s -b "$plugin_jar" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{}' -X POST http://127.0.0.1:5601/api/spike_ask/ask)
if ! echo "$plugin_body" | grep -q '"sub":"alice"'; then
  echo "KO: la route du plugin n'a pas renvoyé l'identité d'alice" >&2
  echo "$plugin_body" >&2
  exit 1
fi
if ! echo "$plugin_body" | grep -q 'equipe-a-viewer'; then
  echo "KO: le groupe equipe-a-viewer n'apparaît pas dans la réponse du plugin" >&2
  echo "$plugin_body" >&2
  exit 1
fi
echo "OK: le plugin spike_ask (asCurrentUser → proxy → moteur) renvoie l'identité d'alice"
echo "    $plugin_body"
echo

echo "== Vecteurs négatifs : jetons forgés, le moteur doit les refuser (F79) =="

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mint_test_jwt construit un JWT RS256 à la main (header.payload.signature),
# sans dépendre d'un outil externe autre qu'openssl : utile uniquement pour
# forger des vecteurs de test volontairement invalides (clé, exp ou aud
# incorrects). Le proxy, lui, utilise la librairie github.com/golang-jwt/jwt
# (voir spike/proxy/main.go, mintJWT) : les deux chemins sont indépendants.
mint_test_jwt() {
  local sub="$1" aud="$2" exp="$3" key="$4"
  local header='{"alg":"RS256","typ":"JWT"}'
  local payload
  payload=$(printf '{"sub":"%s","aud":"%s","exp":%s,"iat":%s,"iss":"spike-proxy","groups":["equipe-a-viewer"]}' \
    "$sub" "$aud" "$exp" "$(date +%s)")
  local h p signing_input sig
  h=$(printf '%s' "$header" | b64url)
  p=$(printf '%s' "$payload" | b64url)
  signing_input="$h.$p"
  sig=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key" -binary | b64url)
  printf '%s.%s' "$signing_input" "$sig"
}

check_rejected() {
  local description="$1" token="$2"
  local code
  code=$("${COMPOSE[@]}" exec -T proxy curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${token}" http://engine:8080/whoami)
  if [ "$code" != "401" ]; then
    echo "KO: $description aurait dû être refusé (401), reçu $code" >&2
    exit 1
  fi
  echo "OK: $description refusé (401)"
}

now=$(date +%s)
expired_token=$(mint_test_jwt alice spike-engine $((now - 3600)) keys/private.pem)
wrong_aud_token=$(mint_test_jwt alice un-autre-service $((now + 300)) keys/private.pem)
wrong_sig_token=$(mint_test_jwt alice spike-engine $((now + 300)) keys/wrong-private.pem)

check_rejected "jeton expiré" "$expired_token"
check_rejected "mauvais destinataire" "$wrong_aud_token"
check_rejected "mauvaise signature" "$wrong_sig_token"
echo

echo "== Témoin positif : un jeton bien formé avec la bonne clé est accepté =="
good_token=$(mint_test_jwt alice spike-engine $((now + 300)) keys/private.pem)
good_code=$("${COMPOSE[@]}" exec -T proxy curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${good_token}" http://engine:8080/whoami)
if [ "$good_code" != "200" ]; then
  echo "KO: un jeton valide forgé avec la bonne clé a été refusé ($good_code)" >&2
  exit 1
fi
echo "OK: accepté (200) — confirme que les refus ci-dessus viennent bien du jeton, pas d'un autre problème"
echo

echo "== SP-06 : critère de réussite atteint =="
echo "    Plugin Kibana réel chargé et fonctionnel, variante jeton-via-Elasticsearch"
echo "    vérifiée de bout en bout (signature, expiration, destinataire)."
