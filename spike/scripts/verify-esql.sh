#!/usr/bin/env bash
# SP-05 : joue FROM, LOOKUP JOIN et ENRICH via le proxy (:9210), d'abord avec
# elastic (capacité brute, aucune ACL), puis avec alice (chemin LDAP ->
# run_as du proxy, SP-03/SP-04), pour répondre à F27 par l'exécution plutôt
# que par la seule doc :
#   1. quelles commandes ES|QL lisent d'autres index en 8.19 ?
#   2. l'ACL native d'Elasticsearch sur l'index (ou la policy) CIBLE d'un
#      LOOKUP JOIN / ENRICH se comporte-t-elle comme pour FROM, ou bien un
#      utilisateur peut-il lire les données d'une autre équipe via un
#      join/enrich malgré une ACL par ailleurs correcte (F27, F14) ?
#
# Prérequis : stack SP-01 à SP-04 démarrée (`docker compose up -d`) et
# ./scripts/esql-seed.sh déjà exécuté.
#
# Ce script n'est volontairement PAS un gate pass/fail comme verify.sh :
# certains résultats attendus sont justement des refus (403), et les deux
# cas marqués "constat ouvert" ci-dessous sont la vraie question du spike,
# pas une régression si le résultat n'est pas celui qu'on espérait. Chaque
# cas imprime le statut HTTP, un extrait du corps, et un verdict ([OK] /
# [CONSTAT]) ; le script ne s'arrête jamais sur un cas individuel.
set -uo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Fichier .env manquant. Lancer : cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

PROXY_URL="http://127.0.0.1:9210"
SURPRISES=0

# run_query USER PASSWORD LABEL QUERY VERDICT_HINT
# VERDICT_HINT : "200" (on attend un succès), "403" (on attend un refus),
# ou "open" (constat ouvert : on ne sait pas encore, les deux issues sont
# informatives, on le signale juste comme tel sans parler d'échec).
run_query() {
  local user="$1" password="$2" label="$3" query="$4" hint="$5"
  local body resp code
  body=$(jq -n --arg q "${query}" '{query: $q}')
  resp=$(curl -s -u "${user}:${password}" -H 'Content-Type: application/json' \
    -o /tmp/sp05-resp.json -w '%{http_code}' \
    -X POST "${PROXY_URL}/_query" -d "${body}")
  code="${resp}"
  local snippet
  snippet=$(head -c 220 /tmp/sp05-resp.json | tr '\n' ' ')

  local verdict
  case "${hint}" in
    200)
      if [ "${code}" = "200" ]; then verdict="[OK] attendu 200, obtenu 200"; else verdict="[CONSTAT] attendu 200, obtenu ${code}"; fi
      ;;
    403)
      if [ "${code}" != "200" ]; then verdict="[OK] attendu refus, obtenu ${code}"; else verdict="[CONSTAT] attendu un refus, obtenu 200 (donnees retournees malgre l'ACL)"; SURPRISES=$((SURPRISES + 1)); fi
      ;;
    open)
      verdict="[CONSTAT OUVERT] reponse ${code} -- voir le corps pour savoir si une autre equipe fuite"
      ;;
  esac

  printf '%-6s %-28s %-60s -> %3s  %s\n' "${user}" "${label}" "${query}" "${code}" "${verdict}"
  printf '       corps: %s\n' "${snippet}"
}

echo "== SP-05 : elastic (superuser, aucune ACL -- capacite brute des commandes) =="
run_query elastic "${ELASTIC_PASSWORD}" control_row \
  'ROW a = 1' 200
run_query elastic "${ELASTIC_PASSWORD}" from_basic \
  'FROM equipe-a-sp05-logs | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" from_list \
  'FROM equipe-a-sp05-logs,equipe-b-sp05-logs | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" from_pattern \
  'FROM equipe-*-sp05-logs | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" from_quoted \
  'FROM "equipe-a-sp05-logs" | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" lookup_same_team \
  'FROM equipe-a-sp05-logs | LOOKUP JOIN equipe-a-sp05-hosts ON host | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" lookup_cross_team \
  'FROM equipe-a-sp05-logs | LOOKUP JOIN equipe-b-sp05-hosts ON host | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" enrich_same_team \
  'FROM equipe-a-sp05-logs | ENRICH sp05-owners-a-policy ON host | LIMIT 5' 200
run_query elastic "${ELASTIC_PASSWORD}" enrich_cross_team \
  'FROM equipe-a-sp05-logs | ENRICH sp05-owners-b-policy ON host | LIMIT 5' 200
echo

echo "== SP-05 : alice (LDAP -> run_as via le proxy, role equipe_a_viewer, pattern equipe-a-*) =="
run_query alice "${ALICE_PASSWORD}" control_row \
  'ROW a = 1' 200
run_query alice "${ALICE_PASSWORD}" from_basic \
  'FROM equipe-a-sp05-logs | LIMIT 5' 200
run_query alice "${ALICE_PASSWORD}" from_list_cross_team \
  'FROM equipe-a-sp05-logs,equipe-b-sp05-logs | LIMIT 5' 403
run_query alice "${ALICE_PASSWORD}" from_pattern_wide \
  'FROM equipe-*-sp05-logs | LIMIT 5' open
run_query alice "${ALICE_PASSWORD}" from_quoted \
  'FROM "equipe-a-sp05-logs" | LIMIT 5' 200
run_query alice "${ALICE_PASSWORD}" lookup_same_team \
  'FROM equipe-a-sp05-logs | LOOKUP JOIN equipe-a-sp05-hosts ON host | LIMIT 5' 200
run_query alice "${ALICE_PASSWORD}" lookup_cross_team \
  'FROM equipe-a-sp05-logs | LOOKUP JOIN equipe-b-sp05-hosts ON host | LIMIT 5' open
run_query alice "${ALICE_PASSWORD}" enrich_same_team \
  'FROM equipe-a-sp05-logs | ENRICH sp05-owners-a-policy ON host | LIMIT 5' 200
run_query alice "${ALICE_PASSWORD}" enrich_cross_team \
  'FROM equipe-a-sp05-logs | ENRICH sp05-owners-b-policy ON host | LIMIT 5' open
echo

echo "Cas marqués [CONSTAT OUVERT] ci-dessus = la vraie question de F27 :"
echo "  - lookup_cross_team (alice) : si le corps contient \"equipe-b-secret\", alice a lu"
echo "    des données d'une autre équipe via LOOKUP JOIN malgré son ACL -- F27 DOIT vérifier"
echo "    l'index cible d'un LOOKUP JOIN, pas seulement le FROM."
echo "  - enrich_cross_team (alice) : si le corps contient \"equipe-b-secret\", même constat"
echo "    pour ENRICH, en pire : la requête ES|QL ne nomme jamais l'index source de la"
echo "    policy, donc un parseur F27 qui ne lit que le texte ne peut pas le voir."
echo
if [ "${SURPRISES}" -gt 0 ]; then
  echo "Attention : ${SURPRISES} cas attendu(s) refusés ont en fait réussi (voir [CONSTAT] ci-dessus)."
fi
echo "Regarder aussi 'docker compose logs proxy | grep _query' pour auth_scheme/run_as/statut."
