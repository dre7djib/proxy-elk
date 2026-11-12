# acceptance run

Script: [`scripts/accept.sh`](../../scripts/accept.sh) (`server` on the Elasticsearch VM, `client` on any other host).

## Run 2026-11-08 — simulated server, NOT a clean VM

Docker Desktop (aarch64): Debian bookworm container with systemd as PID 1; Elasticsearch 8.19.23
in a second container sharing its network namespace, `http.host=127.0.0.1`. Only the
`linux_arm64` archive built by `make release` (v0.0.1) was copied in; `install.sh` created the user,
dirs, binary and unit; secrets were written by hand to `/etc/proxy/secrets` (root:proxy 0640).

| Check | Result |
| --- | --- |
| `accept.sh server`: unit active, user `proxy`, `/health` 200, `-version` = v0.0.1, no world-readable secret | PASS, exit 0 |
| `accept.sh client` from another container, ES on loopback only | PASS, exit 0 |
| same, ES listening on all interfaces (negative control) | FAIL, exit 1 (direct port answered HTTP 401) |

## Not covered

- The ticket's run on a real clean server (real kernel, firewall, native Elasticsearch, amd64 archive,
archive downloaded from a GitHub release). **Still to do by hand**; do not mark the subtask done.
- The "ingest host still reaches 9200" half of F66 (only the loopback/blocked side was exercised).
