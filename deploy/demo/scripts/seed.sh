#!/usr/bin/env bash
# Demo data seed, run after kibana-bootstrap (one-shot
# `seed` service). Adapted from spike/scripts/esql-seed.sh: equipe-a-sample
# and equipe-b-sample already exist (one document each, created by
# spike/scripts/kibana-bootstrap.sh); this script adds a few extra
# logs so Discover is not empty (no ES|QL focus here).
set -euo pipefail

ES_URL="http://elasticsearch:9200"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")

put_doc() {
  local index="$1" id="$2" body="$3"
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index}/_doc/${id}?refresh=true" -d "${body}" >/dev/null
}

echo "Seed equipe-a-sample (extra logs)..."
put_doc equipe-a-sample log-1 '{"team":"equipe-a","message":"request received","host":"web-a1"}'
put_doc equipe-a-sample log-2 '{"team":"equipe-a","message":"error 500","host":"web-a2"}'
echo "OK"

echo "Seed equipe-b-sample (extra logs)..."
put_doc equipe-b-sample log-1 '{"team":"equipe-b","message":"request received","host":"web-b1"}'
echo "OK"

echo "Demo seed complete."
