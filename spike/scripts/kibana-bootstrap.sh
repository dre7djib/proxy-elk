#!/usr/bin/env bash
# Kibana bootstrap for SP-04 (ES roles and Kibana spaces per team).
# Run once in the docker-compose `kibana-setup` service, once
# Kibana responds (depends_on condition: service_healthy): at that point,
# Elasticsearch already has the stub roles and native users created by
# scripts/es-bootstrap.sh (`setup` service), but those stub roles still have
# no privileges (neither index nor Kibana) because `setup` exits before
# Kibana exists.
#
# This script, in order:
#   1. creates the Kibana spaces "equipe-a" and "equipe-b" (one per team,
#      F70/F75) via Kibana's spaces API (POST/PUT /api/spaces/space);
#   2. completes the stub roles equipe_a_viewer / equipe_a_editor /
#      equipe_b_viewer via Kibana's roles API (PUT /api/security/role),
#      NOT Elasticsearch's roles API: the Kibana 8.19 docs are explicit,
#      Kibana privileges (base read/all, spaces) must go through this
#      API to stay consistent with the application privileges Kibana
#      registers with Elasticsearch at startup
#      (application "kibana-.kibana");
#   3. indexes a test document into equipe-a-sample and equipe-b-sample,
#      directly on Elasticsearch (like es-bootstrap.sh for
#      users): used to verify *data* isolation, not
#      only spaces (ticket success criterion);
#   4. creates a minimal dashboard in the "equipe-a" space, for the
#      "bob can edit a dashboard of A" criterion.
#
# Idempotent: spaces and roles are rewritten by PUT (the full definition
# replaces the previous one); the dashboard is created with a fixed id and
# overwrite=true; indexing the test document also uses a fixed id.
# No YAML, no admin level, no generic sync: that comes in
# J2-01/J2-02. Disposable spike code, no tests.
set -euo pipefail

ES_URL="http://elasticsearch:9200"
KIBANA_URL="http://kibana:5601"
ES_AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
KBN_AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
KBN_HEADERS=(-H "kbn-xsrf: true" -H "Content-Type: application/json")

echo "Waiting for Kibana..."
until curl -sf "${KBN_AUTH[@]}" "${KIBANA_URL}/api/status" >/dev/null; do
  sleep 2
done
echo "Kibana ready."

create_or_update_space() {
  local space_id="$1" space_name="$2" space_description="$3"
  echo "Space ${space_id}..."
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' "${KBN_AUTH[@]}" \
    "${KIBANA_URL}/api/spaces/space/${space_id}")
  local payload
  payload=$(cat <<JSON
{
  "id": "${space_id}",
  "name": "${space_name}",
  "description": "${space_description}"
}
JSON
)
  if [ "$status" = "404" ]; then
    curl -sf -X POST "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
      "${KIBANA_URL}/api/spaces/space" -d "${payload}" >/dev/null
    echo "OK (created)"
  else
    curl -sf -X PUT "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
      "${KIBANA_URL}/api/spaces/space/${space_id}" -d "${payload}" >/dev/null
    echo "OK (already present, updated)"
  fi
}

# One space per team (F70, F75). Names distinct from the "default" space created by
# Kibana itself, which no equipe_* role references.
create_or_update_space equipe-a "Team A" "Team A space (SP-04)"
create_or_update_space equipe-b "Team B" "Team B space (SP-04)"

put_kibana_role() {
  local role_name="$1" index_pattern="$2" kibana_base="$3" space_id="$4"
  echo "Kibana role ${role_name} (index ${index_pattern}, base ${kibana_base}, space ${space_id})..."
  curl -sf -X PUT "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
    "${KIBANA_URL}/api/security/role/${role_name}" \
    -d "{
      \"elasticsearch\": {
        \"cluster\": [],
        \"indices\": [
          {
            \"names\": [\"${index_pattern}\"],
            \"privileges\": [\"read\", \"view_index_metadata\"]
          }
        ]
      },
      \"kibana\": [
        {
          \"base\": [\"${kibana_base}\"],
          \"feature\": {},
          \"spaces\": [\"${space_id}\"]
        }
      ]
    }" >/dev/null
  echo "OK"
}

# Full roles per team and level (F74, F75). Kibana's roles API
# fully rewrites the "elasticsearch" and "kibana" sections of the stub role
# created by es-bootstrap.sh: none of the three roles mentions the
# "default" space, so there is no access outside the team's space.
# Editor A: same index privileges as viewer A (read-only on the
# data); only the Kibana base changes (all vs read): editing applies to
# Kibana objects (dashboards) in the space, not to the data itself.
put_kibana_role equipe_a_viewer "equipe-a-*" read equipe-a
put_kibana_role equipe_a_editor "equipe-a-*" all equipe-a
put_kibana_role equipe_b_viewer "equipe-b-*" read equipe-b

index_sample_doc() {
  local index_name="$1" team_label="$2"
  echo "Test document in ${index_name}..."
  curl -sf -X PUT "${ES_AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index_name}/_doc/sample-1?refresh=true" \
    -d "{\"team\":\"${team_label}\",\"message\":\"SP-04 test data\"}" >/dev/null
  echo "OK"
}

# Test data per team (outside the Kibana space itself): used to verify
# that isolation also applies to data via the proxy (ticket success
# criterion and SP-02/F67 finding, not only to Kibana objects
# in the space).
index_sample_doc equipe-a-sample equipe-a
index_sample_doc equipe-b-sample equipe-b

echo "Test dashboard in the equipe-a space..."
curl -sf -X POST "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
  "${KIBANA_URL}/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a?overwrite=true" \
  -d '{
    "attributes": {
      "title": "Team A dashboard (SP-04)",
      "panelsJSON": "[]",
      "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
      "version": 1,
      "timeRestore": false,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
      }
    }
  }' >/dev/null
echo "OK"

echo "Kibana bootstrap complete (SP-04): equipe-a/equipe-b spaces, equipe_a_viewer/equipe_a_editor/equipe_b_viewer roles, test data and dashboard."
