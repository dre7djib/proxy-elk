#!/usr/bin/env bash
# SP-05: run FROM, LOOKUP JOIN and ENRICH via the proxy (:9210), first with
# elastic (raw capability, no ACL), then with alice (LDAP path ->
# proxy run_as, SP-03/SP-04), to answer F27 by execution rather
# than by docs alone:
#   1. which ES|QL commands read other indexes in 8.19?
#   2. does Elasticsearch's native ACL on the TARGET index (or policy) of a
#      LOOKUP JOIN / ENRICH behave like FROM, or can a
#      user read another team's data via a
#      join/enrich despite an otherwise correct ACL (F27, F14)?
#
# Prerequisites: SP-01 to SP-04 stack started (`docker compose up -d`) and
# ./scripts/esql-seed.sh already run.
#
# This script is intentionally NOT a pass/fail gate like verify.sh:
# some expected results are refusals (403), and the two
# cases marked "open finding" below are the spike's real question,
# not a regression if the result is not what we hoped. Each
# case prints the HTTP status, a body snippet, and a verdict ([OK] /
# [FINDING]); the script never stops on an individual case.
set -uo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Missing .env file. Run: cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

PROXY_URL="http://127.0.0.1:9210"
SURPRISES=0

# run_query USER PASSWORD LABEL QUERY VERDICT_HINT
# VERDICT_HINT: "200" (expect success), "403" (expect a refusal),
# or "open" (open finding: we do not know yet, both outcomes are
# informative, just flag it as such without calling it a failure).
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
      if [ "${code}" = "200" ]; then verdict="[OK] expected 200, got 200"; else verdict="[FINDING] expected 200, got ${code}"; fi
      ;;
    403)
      if [ "${code}" != "200" ]; then verdict="[OK] expected refusal, got ${code}"; else verdict="[FINDING] expected a refusal, got 200 (data returned despite the ACL)"; SURPRISES=$((SURPRISES + 1)); fi
      ;;
    open)
      verdict="[OPEN FINDING] response ${code} -- see the body to tell whether another team leaked"
      ;;
  esac

  printf '%-6s %-28s %-60s -> %3s  %s\n' "${user}" "${label}" "${query}" "${code}" "${verdict}"
  printf '       body: %s\n' "${snippet}"
}

echo "== SP-05: elastic (superuser, no ACL -- raw command capability) =="
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

echo "== SP-05: alice (LDAP -> run_as via the proxy, equipe_a_viewer role, equipe-a-* pattern) =="
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

echo "Cases marked [OPEN FINDING] above = F27's real question:"
echo "  - lookup_cross_team (alice): if the body contains \"equipe-b-secret\", alice read"
echo "    another team's data via LOOKUP JOIN despite her ACL -- F27 MUST check"
echo "    the TARGET index of a LOOKUP JOIN, not only the FROM."
echo "  - enrich_cross_team (alice): if the body contains \"equipe-b-secret\", same finding"
echo "    for ENRICH, worse: the ES|QL query never names the policy's source"
echo "    index, so an F27 parser that only reads the text cannot see it."
echo
if [ "${SURPRISES}" -gt 0 ]; then
  echo "Warning: ${SURPRISES} case(s) expected to be refused actually succeeded (see [FINDING] above)."
fi
echo "Also look at 'docker compose logs proxy | grep _query' for auth_scheme/run_as/status."
