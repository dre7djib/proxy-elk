#!/usr/bin/env bash
# Bootstrap Elasticsearch pour la démo J1-13. Dérivé de
# spike/scripts/es-bootstrap.sh (kibana_system, proxy_runas, utilisateurs
# natifs alice/bob/carol pour le gateway Track A) + ajout : clé API ES
# pour le proxy PRODUIT (elasticsearch.api_key, requise par la validation
# de config même si le reverse-proxy produit n'est pas encore câblé, F2).
set -euo pipefail

ES_URL="http://elasticsearch:9200"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")

echo "Waiting for Elasticsearch..."
until curl -s "${AUTH[@]}" "${ES_URL}" >/dev/null; do
  sleep 2
done

echo "Setting kibana_system password..."
until curl -s -X POST "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" \
  | grep -q "^{}"; do
  sleep 2
done
echo "kibana_system ready."

echo "Role proxy_runas (gateway Track A, run_as: alice, bob, carol)..."
curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  "${ES_URL}/_security/role/proxy_runas" \
  -d '{"cluster": [], "indices": [], "run_as": ["alice", "bob", "carol"]}' >/dev/null
echo "OK"

echo "Service user proxy_service (gateway)..."
curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/proxy_service" \
  -d "{\"password\": \"${PROXY_SERVICE_PASSWORD}\", \"roles\": [\"proxy_runas\"], \"full_name\": \"Proxy service (gateway run_as)\"}" >/dev/null
echo "OK"

create_stub_role() {
  local role_name="$1"
  echo "Stub role ${role_name} (complété par kibana-bootstrap.sh)..."
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/role/${role_name}" -d '{"cluster": [], "indices": []}' >/dev/null
  echo "OK"
}
create_stub_role equipe_a_viewer
create_stub_role equipe_a_editor
create_stub_role equipe_b_viewer

create_native_user() {
  local username="$1" full_name="$2" role="$3"
  echo "Native user ${username} (role ${role}, requis pour run_as gateway)..."
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/${username}" \
    -d "{\"password\": \"${NATIVE_SHADOW_PASSWORD}\", \"roles\": [\"${role}\"], \"full_name\": \"${full_name}\"}" >/dev/null
  echo "OK"
}
create_native_user alice "Alice Martin" equipe_a_viewer
create_native_user bob "Bob Durand" equipe_a_editor
create_native_user carol "Carol Petit" equipe_b_viewer

echo "Elasticsearch bootstrap (gateway Track A) complete."
