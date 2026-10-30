#!/usr/bin/env bash
# Seed données de démo J1-13, lancé après kibana-bootstrap (service
# one-shot `seed`). Adapté de spike/scripts/esql-seed.sh : équipe-a-sample
# et équipe-b-sample existent déjà (un doc chacun, créés par
# spike/scripts/kibana-bootstrap.sh) ; ce script ajoute quelques logs
# supplémentaires pour un Discover non trivial (pas de focus ES|QL ici,
# contrairement à SP-05).
set -euo pipefail

ES_URL="http://elasticsearch:9200"
AUTH=(-u "elastic:${ELASTIC_PASSWORD}")

put_doc() {
  local index="$1" id="$2" body="$3"
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index}/_doc/${id}?refresh=true" -d "${body}" >/dev/null
}

echo "Seed equipe-a-sample (logs supplémentaires)..."
put_doc equipe-a-sample log-1 '{"team":"equipe-a","message":"request received","host":"web-a1"}'
put_doc equipe-a-sample log-2 '{"team":"equipe-a","message":"error 500","host":"web-a2"}'
echo "OK"

echo "Seed equipe-b-sample (logs supplémentaires)..."
put_doc equipe-b-sample log-1 '{"team":"equipe-b","message":"request received","host":"web-b1"}'
echo "OK"

echo "Seed démo J1-13 terminé."
