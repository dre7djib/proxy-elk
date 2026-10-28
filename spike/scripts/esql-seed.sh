#!/usr/bin/env bash
# Seed de données pour SP-05 (ES|QL : FROM, LOOKUP JOIN, ENRICH via proxy).
# Lancé à la main depuis spike/ une fois la stack SP-01 à SP-04 démarrée :
#   ./scripts/esql-seed.sh
# Jetable, pas idempotent au sens strict (les policies enrich ne peuvent pas
# être réécrites, voir delete_enrich_policy_if_exists) : relançable sans
# `docker compose down -v` entre deux essais.
#
# Important (constat d'exécution, pas prévu avant de lire SP-04) : SP-04 a
# remplacé les rôles ES built-in (viewer/editor) d'alice/bob/carol par des
# rôles stub + Kibana équipe_a_viewer/equipe_a_editor/equipe_b_viewer,
# restreints au pattern d'index "equipe-a-*" ou "equipe-b-*" (voir
# scripts/es-bootstrap.sh et scripts/kibana-bootstrap.sh). Le plan de SP-05
# supposait encore le rôle built-in "viewer" (accès large) : avec des index
# nommés "sp05-*", alice n'aurait pu lire AUCUN d'entre eux et tout test via
# son identité LDAP aurait échoué par construction, sans rien démontrer sur
# ES|QL lui-même.
#
# Adaptation retenue : nommer les index selon le pattern réel d'alice
# (equipe-a-*) et créer en plus un jeu "equipe-b-*" qu'elle n'a PAS le droit
# de lire. Ça permet de répondre à la vraie question de F27 : est-ce que
# LOOKUP JOIN et ENRICH respectent l'ACL native d'Elasticsearch sur l'index
# ou la policy *cible*, au même titre que FROM, ou bien un utilisateur
# peut-il lire les données d'une autre équipe via un join/enrich malgré une
# ACL par ailleurs correcte sur l'index source ? C'est exactement le risque
# que F27 doit couvrir.
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
  # Supprime puis recree a chaque run : LOOKUP JOIN exige que le champ de
  # jointure soit de type "keyword" (constat d'execution, voir plus bas) ;
  # un index deja cree avec un mapping dynamique "text" ne peut pas etre
  # corrige par un simple PUT mapping apres coup pour un champ existant.
  curl -s -X DELETE "${AUTH[@]}" "${ES_URL}/${index}" >/dev/null 2>&1 || true
  curl -sf -X PUT "${AUTH[@]}" -H "Content-Type: application/json" \
    "${ES_URL}/${index}" -d "${settings_json}" >/dev/null
  echo "OK (recree)"
}

echo "== SP-05 : index FROM (logs) =="
# "host" en keyword explicite (pas de mapping dynamique "text") : requis
# cote index LOOKUP pour le champ de jointure (voir plus bas), et garde la
# coherence de type entre FROM et LOOKUP JOIN pour que "ON host" matche.
LOGS_MAPPING='{"mappings":{"properties":{"host":{"type":"keyword"},"message":{"type":"text"}}}}'
HOSTS_MAPPING='{"settings":{"index.mode":"lookup"},"mappings":{"properties":{"host":{"type":"keyword"},"owner":{"type":"keyword"}}}}'

# equipe-a-sp05-logs : lisible par alice (equipe_a_viewer, pattern equipe-a-*).
create_index equipe-a-sp05-logs "${LOGS_MAPPING}"
put_doc equipe-a-sp05-logs 1 '{"host":"web-a1","message":"requete recue"}'
put_doc equipe-a-sp05-logs 2 '{"host":"web-a2","message":"erreur 500"}'

# equipe-b-sp05-logs : hors du pattern d'alice, sert de temoin negatif pour
# la commande FROM (liste d'index ou pattern elargi).
create_index equipe-b-sp05-logs "${LOGS_MAPPING}"
put_doc equipe-b-sp05-logs 1 '{"host":"web-b1","message":"requete recue"}'

echo
echo "== SP-05 : index LOOKUP (index.mode: lookup) =="
# equipe-a-sp05-hosts : lookup index lisible par alice, meme equipe que le
# FROM ci-dessus (cas "legitime", doit reussir).
create_index equipe-a-sp05-hosts "${HOSTS_MAPPING}"
put_doc equipe-a-sp05-hosts web-a1 '{"host":"web-a1","owner":"equipe-a"}'
put_doc equipe-a-sp05-hosts web-a2 '{"host":"web-a2","owner":"equipe-a"}'

# equipe-b-sp05-hosts : lookup index d'une AUTRE equipe. Cas critique pour
# F27 : alice (equipe-a-sp05-logs) peut-elle faire
#   LOOKUP JOIN equipe-b-sp05-hosts ON host
# et recuperer malgre tout des donnees de l'equipe B ?
create_index equipe-b-sp05-hosts "${HOSTS_MAPPING}"
put_doc equipe-b-sp05-hosts web-a1 '{"host":"web-a1","owner":"equipe-b-secret"}'
put_doc equipe-b-sp05-hosts web-a2 '{"host":"web-a2","owner":"equipe-b-secret"}'

echo
echo "== SP-05 : index source + policy ENRICH =="
# Deux sources, une par equipe, pour les memes raisons que les lookup index
# ci-dessus : savoir si ENRICH respecte l'equipe du policy source cote ACL,
# sachant que la requete ES|QL ne nomme JAMAIS l'index source (seulement le
# nom de la policy), constat deja fait en lisant la doc avant le spike.
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
  echo "OK (creee et executee)"
}

create_and_execute_policy sp05-owners-a-policy equipe-a-sp05-owners
create_and_execute_policy sp05-owners-b-policy equipe-b-sp05-owners

echo
echo "Seed SP-05 termine :"
echo "  FROM        : equipe-a-sp05-logs (lisible par alice), equipe-b-sp05-logs (temoin negatif)"
echo "  LOOKUP JOIN : equipe-a-sp05-hosts (meme equipe), equipe-b-sp05-hosts (autre equipe, lookup index)"
echo "  ENRICH      : sp05-owners-a-policy / sp05-owners-b-policy (policy, pas un nom d'index dans la requete)"
