#!/usr/bin/env bash
# J1-19 acceptance for the binary install (docs/installation.md, cas 3).
#
#   server (on the Elasticsearch VM, as root, after install.sh + secrets):
#     EXPECT_VERSION=v0.0.1 ./accept.sh server
#     unit active, runs as a non-root user, /health answers, `proxy -version`
#     matches, no secret file is world-readable.
#
#   client (on a host that is neither the proxy nor an ingest host, e.g. Kibana's):
#     ES_DIRECT_URL=http://es-vm:9200 PROXY_URL=http://es-vm:8080 \
#     ACCEPT_USER=kibana_system ACCEPT_PASSWORD=... ./accept.sh client
#     F66: Elasticsearch's own port gives no answer; a request through the
#     proxy succeeds. Any HTTP answer from the direct port (even 401) fails.
set -u

fails=0
ok()   { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
need() { [ -n "${!1:-}" ] || { echo "missing env $1" >&2; exit 2; }; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }

server() {
  need EXPECT_VERSION
  local url=${PROXY_URL:-http://127.0.0.1:8080} unit=proxy-elk pid user

  systemctl is-active --quiet "$unit" && ok "unit $unit active" || fail "unit $unit not active"

  pid=$(systemctl show -p MainPID --value "$unit")
  user=$([ "${pid:-0}" -gt 0 ] && stat -c %U "/proc/$pid" 2>/dev/null || true)
  if [ -n "$user" ] && [ "$user" != root ]; then ok "runs as non-root user $user"
  else fail "service user is '${user:-unknown}' (want a non-root user)"; fi

  [ "$(code "$url/health")" = 200 ] && ok "GET /health 200" || fail "GET $url/health not 200"

  got=$(/usr/local/bin/proxy -version 2>&1)
  [ "$got" = "$EXPECT_VERSION" ] && ok "proxy -version = $got" || fail "proxy -version '$got', want '$EXPECT_VERSION'"

  bad=$(find /etc/proxy/secrets -type f -perm -o+r 2>/dev/null)
  [ -z "$bad" ] && ok "no world-readable secret file" || fail "world-readable secrets: $bad"
}

client() {
  need ES_DIRECT_URL; need PROXY_URL; need ACCEPT_USER; need ACCEPT_PASSWORD
  c=$(code "$ES_DIRECT_URL")
  [ "$c" = 000 ] && ok "F66 direct $ES_DIRECT_URL gives no answer" || fail "F66 direct $ES_DIRECT_URL answered HTTP $c"
  c=$(code -u "$ACCEPT_USER:$ACCEPT_PASSWORD" "$PROXY_URL/")
  [ "$c" = 200 ] && ok "request through proxy 200" || fail "request through $PROXY_URL got HTTP $c"
}

case "${1:-}" in
  server) server ;;
  client) client ;;
  *) echo "usage: accept.sh server|client" >&2; exit 2 ;;
esac
[ "$fails" -eq 0 ]
