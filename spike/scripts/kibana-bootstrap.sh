#!/usr/bin/env bash
# Bootstrap Kibana pour SP-04 (rôles ES et spaces Kibana par équipe).
# Lancé une fois dans le service `kibana-setup` du docker-compose, une fois
# que Kibana répond (depends_on condition: service_healthy) : à ce stade,
# Elasticsearch a déjà les rôles stub et les utilisateurs natifs créés par
# scripts/es-bootstrap.sh (service `setup`), mais ces rôles stub n'ont encore
# aucun privilège (ni index, ni Kibana) car `setup` se termine avant que
# Kibana n'existe.
#
# Ce script, dans l'ordre :
#   1. crée les spaces Kibana "equipe-a" et "equipe-b" (un par équipe,
#      F70/F75) via l'API spaces de Kibana (POST/PUT /api/spaces/space) ;
#   2. complète les rôles stub equipe_a_viewer / equipe_a_editor /
#      equipe_b_viewer via l'API rôles de Kibana (PUT /api/security/role),
#      PAS l'API rôles d'Elasticsearch : la doc Kibana 8.19 est explicite,
#      les privilèges Kibana (base read/all, spaces) doivent passer par cette
#      API pour rester cohérents avec les privilèges applicatifs que Kibana
#      enregistre lui-même auprès d'Elasticsearch au démarrage
#      (application "kibana-.kibana") ;
#   3. indexe un document de test dans equipe-a-sample et equipe-b-sample,
#      directement sur Elasticsearch (comme es-bootstrap.sh pour les
#      utilisateurs) : sert à vérifier l'isolation des *données*, pas
#      seulement des spaces (critère de réussite du ticket) ;
#   4. crée un dashboard minimal dans le space "equipe-a", pour le critère
#      « bob peut modifier un dashboard de A ».
#
# Idempotent : spaces et rôles sont réécrits par PUT (la définition complète
# remplace l'ancienne) ; le dashboard est créé avec un id fixe et
# overwrite=true ; l'indexation du document de test utilise aussi un id fixe.
# Pas de YAML, pas de niveau admin, pas de synchro générique : ça arrive en
# J2-01/J2-02. Code jetable du spike, pas de tests.
set -euo pipefail

ES_URL="http://elasticsearch:9200"
KIBANA_URL="http://kibana:5601"
ES_AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
KBN_AUTH=(-u "elastic:${ELASTIC_PASSWORD}")
KBN_HEADERS=(-H "kbn-xsrf: true" -H "Content-Type: application/json")

echo "Attente de Kibana..."
until curl -sf "${KBN_AUTH[@]}" "${KIBANA_URL}/api/status" >/dev/null; do
  sleep 2
done
echo "Kibana pret."

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
    echo "OK (cree)"
  else
    curl -sf -X PUT "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
      "${KIBANA_URL}/api/spaces/space/${space_id}" -d "${payload}" >/dev/null
    echo "OK (deja present, mis a jour)"
  fi
}

# Un space par équipe (F70, F75). Noms distincts du space "default" créé par
# Kibana lui-même, qu'aucun rôle equipe_* ne référence.
create_or_update_space equipe-a "Equipe A" "Space de l'equipe A (SP-04)"
create_or_update_space equipe-b "Equipe B" "Space de l'equipe B (SP-04)"

put_kibana_role() {
  local role_name="$1" index_pattern="$2" kibana_base="$3" space_id="$4"
  echo "Role Kibana ${role_name} (index ${index_pattern}, base ${kibana_base}, space ${space_id})..."
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

# Rôles complets par équipe et niveau (F74, F75). L'API rôles de Kibana
# réécrit entièrement les sections "elasticsearch" et "kibana" du rôle stub
# créé par es-bootstrap.sh : aucun des trois rôles ne mentionne le space
# "default", donc aucun accès hors du space de son équipe.
# Editor A : mêmes privilèges d'index que viewer A (lecture seule sur les
# données), seule la base Kibana change (all vs read) : l'édition porte sur
# les objets Kibana (dashboards) du space, pas sur les données elles-mêmes.
put_kibana_role equipe_a_viewer "equipe-a-*" read equipe-a
put_kibana_role equipe_a_editor "equipe-a-*" all equipe-a
put_kibana_role equipe_b_viewer "equipe-b-*" read equipe-b

index_sample_doc() {
  local index_name="$1" team_label="$2"
  echo "Document de test dans ${index_name}..."
  curl -sf -X PUT "${ES_AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index_name}/_doc/sample-1?refresh=true" \
    -d "{\"team\":\"${team_label}\",\"message\":\"donnee de test SP-04\"}" >/dev/null
  echo "OK"
}

# Données de test par équipe (hors du seul space Kibana) : sert à vérifier
# que l'isolation porte aussi sur les données via le proxy (critère de
# réussite du ticket et constat SP-02/F67, pas seulement sur les objets
# Kibana du space).
index_sample_doc equipe-a-sample equipe-a
index_sample_doc equipe-b-sample equipe-b

echo "Dashboard de test dans le space equipe-a..."
curl -sf -X POST "${KBN_AUTH[@]}" "${KBN_HEADERS[@]}" \
  "${KIBANA_URL}/s/equipe-a/api/saved_objects/dashboard/spike-dashboard-equipe-a?overwrite=true" \
  -d '{
    "attributes": {
      "title": "Dashboard equipe A (SP-04)",
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

echo "Bootstrap Kibana termine (SP-04) : spaces equipe-a/equipe-b, roles equipe_a_viewer/equipe_a_editor/equipe_b_viewer, donnees et dashboard de test."
