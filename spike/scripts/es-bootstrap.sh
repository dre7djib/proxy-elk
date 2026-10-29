#!/usr/bin/env bash
# Elasticsearch bootstrap for SP-03/SP-04 (continues the SP-01 bootstrap).
# Run once in the docker-compose `setup` service, once
# Elasticsearch responds:
#   1. set the kibana_system password (carried over from SP-01/SP-02);
#   2. create the proxy_runas role (run_as alice, bob, carol) and the
#      proxy_service service user, which the proxy uses to impersonate
#      LDAP users (F2, F4, SP-03);
#   3. create ES "stub" roles per team and level (equipe_a_viewer,
#      equipe_a_editor, equipe_b_viewer, SP-04): this service exits before
#      Kibana is reachable (depends_on service_healthy on
#      Elasticsearch only), so Kibana privileges (spaces, base read/all)
#      cannot be set here. The role exists only so assigning it to the user
#      does not reference an unknown role; it is then completed (indexes +
#      Kibana privileges) by scripts/kibana-bootstrap.sh once Kibana has
#      started (PUT via Kibana's roles API, which fully rewrites the
#      role definition);
#   4. create the native users alice/bob/carol: `run_as` fails if
#      the target user does not exist on the Elasticsearch side, even if they
#      exist in the directory. Elasticsearch has no LDAP realm here (paid
#      feature): these accounts' LDAP password (the one the user types in
#      Kibana) is validated by the proxy via search-then-bind, never
#      by Elasticsearch.
#
# SP-03 runtime finding: their ES password CANNOT be random and discarded.
# Kibana calls POST /_security/profile/_activate right after
# login (grant_type: "password", with the password typed by the user),
# authenticated as kibana_system but verified by Elasticsearch itself
# against its native realm. Without a known native password, that exact
# step fails with 401 and blocks the whole Kibana login. Hence NATIVE_SHADOW_PASSWORD:
# a shared secret, known only to the proxy (which substitutes it in that one
# call after re-checking the LDAP password) and this script — never
# typed by a user, never sent to LDAP, never logged.
# Idempotent: re-running the script (e.g. `docker compose up` without -v) just
# updates the same objects.
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
curl -sf -X PUT "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  "${ES_URL}/_security/role/proxy_runas" \
  -d '{
    "cluster": [],
    "indices": [],
    "run_as": ["alice", "bob", "carol"]
  }' >/dev/null
echo "OK"

echo "Service user proxy_service..."
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
  echo "Native user ${username} (role ${role}, required for run_as)..."
  curl -sf -X PUT "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    "${ES_URL}/_security/user/${username}" \
    -d "{
      \"password\": \"${NATIVE_SHADOW_PASSWORD}\",
      \"roles\": [\"${role}\"],
      \"full_name\": \"${full_name}\"
    }" >/dev/null
  echo "OK (native password = shared proxy/bootstrap secret, never typed by the user)"
}

create_stub_role() {
  local role_name="$1"
  echo "Stub role ${role_name} (completed later by kibana-bootstrap.sh, SP-04)..."
  curl -sf -X PUT "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    "${ES_URL}/_security/role/${role_name}" \
    -d '{
      "cluster": [],
      "indices": []
    }' >/dev/null
  echo "OK"
}

# Stub roles per team and level (SP-04): team A (viewer, editor) and
# team B (viewer). Replaces the built-in viewer/editor roles from SP-03, which
# granted access to all Kibana spaces with no team isolation.
# kibana-bootstrap.sh (run after Kibana, in the kibana-setup service)
# completes these roles: team index + Kibana privileges (base read/all,
# team space). Without it, alice/bob/carol have access to no index and
# no space: a short, acceptable window between the two setup services.
create_stub_role equipe_a_viewer
create_stub_role equipe_a_editor
create_stub_role equipe_b_viewer

create_native_user alice "Alice Martin" equipe_a_viewer
create_native_user bob "Bob Durand" equipe_a_editor
create_native_user carol "Carol Petit" equipe_b_viewer

echo "Elasticsearch bootstrap complete (SP-01 to SP-04)."
