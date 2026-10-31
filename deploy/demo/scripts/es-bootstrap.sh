#!/usr/bin/env bash
# Bootstrap Elasticsearch pour la démo J1-13/J1-15. Dérivé de
# spike/scripts/es-bootstrap.sh (kibana_system, proxy_runas, utilisateurs
# natifs alice/bob/carol, utilisés par le relais ES du proxy PRODUIT
# depuis J1-15) + une clé API ES dédiée au résolveur d'index ACL (F15),
# écrite dans le volume partagé `essecrets` (jamais en .env statique).
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

echo "Role proxy_runas (run_as: alice, bob, carol)..."
curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  "${ES_URL}/_security/role/proxy_runas" \
  -d '{"cluster": [], "indices": [], "run_as": ["alice", "bob", "carol"]}' >/dev/null
echo "OK"

echo "Service user proxy_service (relay run_as, J1-15)..."
curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
  "${ES_URL}/_security/user/proxy_service" \
  -d "{\"password\": \"${PROXY_SERVICE_PASSWORD}\", \"roles\": [\"proxy_runas\"], \"full_name\": \"Proxy service (relay run_as)\"}" >/dev/null
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
  echo "Native user ${username} (role ${role}, requis pour run_as)..."
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/${username}" \
    -d "{\"password\": \"${NATIVE_SHADOW_PASSWORD}\", \"roles\": [\"${role}\"], \"full_name\": \"${full_name}\"}" >/dev/null
  echo "OK"
}
create_native_user alice "Alice Martin" equipe_a_viewer
create_native_user bob "Bob Durand" equipe_a_editor
create_native_user carol "Carol Petit" equipe_b_viewer

echo "API key for the proxy's index resolver (view_index_metadata, F15)..."
api_key_response=$(curl -sf -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
  "${ES_URL}/_security/api_key" \
  -d '{"name":"proxy-resolver","role_descriptors":{"proxy_resolver":{"cluster":[],"indices":[{"names":["*"],"privileges":["view_index_metadata"]}]}}}')
api_key_id=$(echo "${api_key_response}" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
api_key_secret=$(echo "${api_key_response}" | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "${api_key_id}" ] || [ -z "${api_key_secret}" ]; then
  echo "Failed to create ES API key: ${api_key_response}" >&2
  exit 1
fi
mkdir -p /secrets
printf '%s' "${api_key_id}:${api_key_secret}" | base64 -w0 > /secrets/es-api-key
chmod 644 /secrets/es-api-key
echo "OK"

echo "Elasticsearch bootstrap (produit, J1-13/J1-15) complete."
