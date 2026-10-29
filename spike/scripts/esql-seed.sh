#!/usr/bin/env bash
# Data seed for SP-05 (ES|QL: FROM, LOOKUP JOIN, ENRICH via proxy).
# Run by hand from spike/ once the SP-01 to SP-04 stack is up:
#   ./scripts/esql-seed.sh
# Disposable, not strictly idempotent (enrich policies cannot be
# rewritten, see delete_enrich_policy_if_exists): re-runnable without
# `docker compose down -v` between attempts.
#
# Important (runtime finding, not anticipated before reading SP-04): SP-04
# replaced alice/bob/carol's built-in ES roles (viewer/editor) with
# stub + Kibana equipe_a_viewer/equipe_a_editor/equipe_b_viewer roles,
# restricted to the "equipe-a-*" or "equipe-b-*" index pattern (see
# scripts/es-bootstrap.sh and scripts/kibana-bootstrap.sh). The SP-05 plan
# still assumed the built-in "viewer" role (broad access): with indexes
# named "sp05-*", alice would have been able to read NONE of them and any test via
# her LDAP identity would have failed by construction, without demonstrating anything about
# ES|QL itself.
#
# Adaptation chosen: name indexes according to alice's real pattern
# (equipe-a-*) and also create an "equipe-b-*" set she is NOT allowed
# to read. That lets us answer F27's real question: do
# LOOKUP JOIN and ENRICH respect Elasticsearch's native ACL on the *target*
# index or policy, the same way FROM does, or can a user
# read another team's data via a join/enrich despite an
# otherwise correct ACL on the source index? That is exactly the risk
# F27 must cover.
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

ES_URL="http://127.0.0.1:9200"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")

put_doc() {
  local index="$1" id="$2" body="$3"
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index}/_doc/${id}?refresh=true" -d "${body}" >/dev/null
}

create_index() {
  local index="$1" settings_json="$2"
  echo "Index ${index}..."
  # Delete then recreate on every run: LOOKUP JOIN requires the join
  # field to be type "keyword" (runtime finding, see below);
  # an index already created with a dynamic "text" mapping cannot be
  # fixed by a simple PUT mapping afterwards for an existing field.
  curl -s -X DELETE "${AUTH[@]}" "${ES_URL}/${index}" >/dev/null 2>&1 || true
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index}" -d "${settings_json}" >/dev/null
  echo "OK (recreated)"
}

echo "== SP-05: FROM indexes (logs) =="
# "host" as an explicit keyword (no dynamic "text" mapping): required
# on the LOOKUP index side for the join field (see below), and keeps
# type consistency between FROM and LOOKUP JOIN so "ON host" matches.
LOGS_MAPPING='{"mappings":{"properties":{"host":{"type":"keyword"},"message":{"type":"text"}}}}'
HOSTS_MAPPING='{"settings":{"index.mode":"lookup"},"mappings":{"properties":{"host":{"type":"keyword"},"owner":{"type":"keyword"}}}}'

# equipe-a-sp05-logs: readable by alice (equipe_a_viewer, equipe-a-* pattern).
create_index equipe-a-sp05-logs "${LOGS_MAPPING}"
put_doc equipe-a-sp05-logs 1 '{"host":"web-a1","message":"request received"}'
put_doc equipe-a-sp05-logs 2 '{"host":"web-a2","message":"error 500"}'

# equipe-b-sp05-logs: outside alice's pattern, used as a negative control for
# the FROM command (index list or widened pattern).
create_index equipe-b-sp05-logs "${LOGS_MAPPING}"
put_doc equipe-b-sp05-logs 1 '{"host":"web-b1","message":"request received"}'

echo
echo "== SP-05: LOOKUP indexes (index.mode: lookup) =="
# equipe-a-sp05-hosts: lookup index readable by alice, same team as the
# FROM above ("legitimate" case, must succeed).
create_index equipe-a-sp05-hosts "${HOSTS_MAPPING}"
put_doc equipe-a-sp05-hosts web-a1 '{"host":"web-a1","owner":"equipe-a"}'
put_doc equipe-a-sp05-hosts web-a2 '{"host":"web-a2","owner":"equipe-a"}'

# equipe-b-sp05-hosts: lookup index of ANOTHER team. Critical case for
# F27: can alice (equipe-a-sp05-logs) run
#   LOOKUP JOIN equipe-b-sp05-hosts ON host
# and still recover team B data?
create_index equipe-b-sp05-hosts "${HOSTS_MAPPING}"
put_doc equipe-b-sp05-hosts web-a1 '{"host":"web-a1","owner":"equipe-b-secret"}'
put_doc equipe-b-sp05-hosts web-a2 '{"host":"web-a2","owner":"equipe-b-secret"}'

echo
echo "== SP-05: ENRICH source indexes + policy =="
# Two sources, one per team, for the same reasons as the lookup indexes
# above: tell whether ENRICH respects the policy source team's ACL,
# given that the ES|QL query NEVER names the source index (only the
# policy name), a finding already made from the docs before the spike.
create_index equipe-a-sp05-owners '{}'
put_doc equipe-a-sp05-owners web-a1 '{"host":"web-a1","owner":"equipe-a"}'
put_doc equipe-a-sp05-owners web-a2 '{"host":"web-a2","owner":"equipe-a"}'

create_index equipe-b-sp05-owners '{}'
put_doc equipe-b-sp05-owners web-a1 '{"host":"web-a1","owner":"equipe-b-secret"}'
put_doc equipe-b-sp05-owners web-a2 '{"host":"web-a2","owner":"equipe-b-secret"}'

delete_enrich_policy_if_exists() {
  local policy="$1"
  curl -s -X DELETE "${AUTH[@]}" "${ES_URL}/_enrich/policy/${policy}" >/dev/null 2>&1 || true
}

create_and_execute_policy() {
  local policy="$1" source_index="$2"
  echo "Policy ${policy} (source ${source_index})..."
  delete_enrich_policy_if_exists "${policy}"
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/_enrich/policy/${policy}" -d "{
      \"match\": {
        \"indices\": \"${source_index}\",
        \"match_field\": \"host\",
        \"enrich_fields\": [\"owner\"]
      }
    }" >/dev/null
  curl -sf -X POST "${AUTH[@]}" "${ES_URL}/_enrich/policy/${policy}/_execute" >/dev/null
  echo "OK (created and executed)"
}

create_and_execute_policy sp05-owners-a-policy equipe-a-sp05-owners
create_and_execute_policy sp05-owners-b-policy equipe-b-sp05-owners

echo
echo "SP-05 seed complete:"
echo "  FROM        : equipe-a-sp05-logs (readable by alice), equipe-b-sp05-logs (negative control)"
echo "  LOOKUP JOIN : equipe-a-sp05-hosts (same team), equipe-b-sp05-hosts (other team, lookup index)"
echo "  ENRICH      : sp05-owners-a-policy / sp05-owners-b-policy (policy, not an index name in the query)"
