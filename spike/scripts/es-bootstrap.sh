#!/usr/bin/env bash
# Bootstrap Elasticsearch pour SP-03 (prend la suite du bootstrap SP-01).
# Lancé une fois dans le service `setup` du docker-compose, une fois
# qu'Elasticsearch répond :
#   1. règle le mot de passe de kibana_system (repris de SP-01/SP-02) ;
#   2. crée le rôle proxy_runas (run_as alice, bob, carol) et l'utilisateur
#      de service proxy_service, que le proxy utilise pour usurper l'identité
#      des utilisateurs LDAP (F2, F4, SP-03) ;
#   3. crée les utilisateurs natifs alice/bob/carol : `run_as` échoue si
#      l'utilisateur ciblé n'existe pas côté Elasticsearch, même s'il existe
#      dans l'annuaire. Elasticsearch n'a pas de realm LDAP ici (fonction
#      payante) : le mot de passe LDAP de ces comptes (celui que l'utilisateur
#      tape dans Kibana) est validé par le proxy via search-then-bind, jamais
#      par Elasticsearch.
#
# Constat d'exécution SP-03 : leur mot de passe ES ne peut PAS être aléatoire
# et jeté. Kibana appelle POST /_security/profile/_activate juste après le
# login (grant_type: "password", avec le mot de passe tapé par l'utilisateur),
# authentifié avec kibana_system mais vérifié par Elasticsearch lui-même
# contre son realm natif. Sans mot de passe natif connu, ce point précis
# échoue en 401 et bloque tout le login Kibana. D'où NATIVE_SHADOW_PASSWORD :
# un secret partagé, connu seulement du proxy (qui le substitue dans ce seul
# appel après avoir revérifié le mot de passe LDAP) et de ce script — jamais
# tapé par un utilisateur, jamais transmis à LDAP, jamais journalisé.
# Idempotent : relancer le script (ex. `docker compose up` sans -v) met juste
# à jour les mêmes objets.
set -euo pipefail

ES_URL="http://elasticsearch:9200"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")

echo "Attente d'Elasticsearch..."
until curl -s "${AUTH[@]}" "${ES_URL}" >/dev/null; do
  sleep 2
done

echo "Definition du mot de passe de kibana_system..."
until curl -s -X POST "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" \
  | grep -q "^{}"; do
  sleep 2
done
echo "kibana_system pret."

echo "Role proxy_runas (run_as: alice, bob, carol)..."
curl -sf -X PUT "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/role/proxy_runas" \
  -d '{
    "cluster": [],
    "indices": [],
    "run_as": ["alice", "bob", "carol"]
  }' >/dev/null
echo "OK"

echo "Utilisateur de service proxy_service..."
curl -sf -X PUT "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/proxy_service" \
  -d "{
    \"password\": \"${PROXY_SERVICE_PASSWORD}\",
    \"roles\": [\"proxy_runas\"],
    \"full_name\": \"Proxy service (run_as, SP-03)\"
  }" >/dev/null
echo "OK"

create_native_user() {
  local username="$1" full_name="$2" role="$3"
  echo "Utilisateur natif ${username} (role ${role}, requis pour run_as)..."
  curl -sf -X PUT "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/${username}" \
    -d "{
      \"password\": \"${NATIVE_SHADOW_PASSWORD}\",
      \"roles\": [\"${role}\"],
      \"full_name\": \"${full_name}\"
    }" >/dev/null
  echo "OK (mot de passe natif = secret partage proxy/bootstrap, jamais tape par l'utilisateur)"
}

# Rôles built-in Elasticsearch (viewer = lecture seule, editor = lecture et
# modification des objets Kibana) : l'isolation par équipe (spaces, F70-F77)
# arrive en SP-04, hors périmètre de SP-03.
create_native_user alice "Alice Martin" viewer
create_native_user bob "Bob Durand" editor
create_native_user carol "Carol Petit" viewer

echo "Bootstrap Elasticsearch termine (SP-01 a SP-03)."
