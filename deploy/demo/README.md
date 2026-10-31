# proxy-elk demo (J1-13/J1-12/J1-15, F68/F66/F69/F2)

Full demo in **one command**, derived from [`spike/`](../../spike) (SP-01
through SP-06) — `spike/` is left unchanged; this directory does not modify it.

```sh
cd deploy/demo
cp .env.example .env
docker compose up -d
./scripts/verify.sh
```

Stop: `docker compose down` (add `-v` to start from scratch: ES,
LDAP and session data live in named volumes).

## One proxy

The **product** binary (repo root, `Dockerfile` image, J1-11) is the
**only** Kibana → Elasticsearch path in this demo. It exposes `/health`,
`/metrics`, `/auth/ldap` (LDAPS), `/auth/login` + `/auth/callback` (OIDC
Keycloak), `/auth/me`, and — since J1-15 (F2) — relays Elasticsearch calls:
LDAP/session/JWT identity resolved, ACL decided (`internal/acl`), then
forwarded upstream as the `proxy_service` service account with
`es-security-runas-user` impersonating the caller. The caller's own
password never reaches Elasticsearch. `POST /_security/profile/_activate`
(Kibana login) gets its body's password substituted with a shared native
secret once the caller's LDAP password is re-checked (`internal/es`). The
spike's old `gateway` (Track A) has been retired from this demo.

## Services

| Service         | Role                                                                  |
|-----------------|-----------------------------------------------------------------------|
| `certs`         | Generates the demo LDAPS CA + server cert (one-shot, idempotent)      |
| `elasticsearch` | Single-node cluster, native security enabled, `es` network only (no host port, F66) |
| `setup`         | ES bootstrap: `kibana_system`, `proxy_runas`, users alice/bob/carol, resolver API key (F15) |
| `engine`        | Verifies the signed token (SP-06), separate process from the proxy    |
| `openldap`      | Test directory (alice/bob/carol), plaintext LDAP 389 + LDAPS 636      |
| `keycloak`      | Demo OIDC IdP, realm `demo` imported (client `proxy`, same users)     |
| `kibana`        | Kibana 8.19 + spike_ask plugin (build `spike/kibana`)                 |
| `kibana-setup`  | Per-team Kibana spaces/roles (reuses `spike/scripts/kibana-bootstrap.sh`) |
| `seed`          | Extra demo logs into `equipe-a/b-sample`                              |
| `proxy`         | Product image: `/health`, `/metrics`, `/auth/*`, ES relay (J1-15)     |
| `kdc`           | MIT KDC, realm `EXAMPLE.ORG`, generates the proxy's keytab on first boot |
| `krb5-user`     | `kinit` + `curl --negotiate` client for the SPNEGO smoke test          |

## LDAP TLS (F5)

`gen-certs.sh` generates a throwaway CA and server certificate under
`certs/` (never committed; see `certs/.gitignore`) before `openldap`
starts. The **product** proxy connects with `ldaps://openldap:636` using
that CA (`configs/proxy.yaml`, `ldap.ca_file`) — one LDAPS connection for
both `/auth/ldap` and the ES relay's run_as checks (J1-15). Plaintext port
389 stays exposed for a direct LDAP client, but the product doesn't use it.

## OIDC (Keycloak)

The `demo` realm (`keycloak/realm-export.json`) defines the `proxy` client
and users alice/bob/carol with a `groups` attribute (same group names as
the spike LDIF: `equipe-a-viewer`, `equipe-a-editor`, `equipe-b-viewer`).
The client secret is **committed in plaintext**
(`demo-oidc-secret-change-me`): a throwaway demo secret, never a prod
value.

The product proxy always reaches Keycloak via `http://keycloak:18080`
(Docker DNS), so its `oidc.issuer` stays stable. Port 18080 avoids
clashing with anything already on host port 8080. For a **full interactive
login** in a browser (not only the 302 smoke test in `verify.sh`), the
browser must also resolve `keycloak` to `127.0.0.1` (otherwise the auth
redirect goes nowhere):

```sh
echo "127.0.0.1 keycloak" | sudo tee -a /etc/hosts
```

Then open `http://127.0.0.1:8081/auth/login`.

## Kerberos SPNEGO SSO

With `kerberos:` set in `configs/proxy.yaml`, `GET /auth/kibana` stops
rendering the login form: it becomes the SPNEGO/Negotiate
challenge/response, so a browser with a valid Kerberos ticket reaches
Kibana with zero fields typed. The demo's `kdc` service provisions a
realm `EXAMPLE.ORG` with a principal `alice` (same password as the LDAP
LDIF, `ALICE_PASSWORD`) and the proxy's keytab, generated at first boot
and mounted read-only into `proxy` — the proxy container itself needs no
`krb5.conf`, since accepting a client's ticket via keytab never contacts
the KDC.

To try it from a browser (not just `verify.sh`'s smoke test), the ticket
must be for the hostname in the URL, so add it to `/etc/hosts` and
`kinit` against the KDC (published on `127.0.0.1:88`):

```sh
echo "127.0.0.1 proxy.demo.local" | sudo tee -a /etc/hosts
kinit alice@EXAMPLE.ORG    # uses the host's krb5.conf; point it at the
                           # demo realm, or run kinit inside krb5-user
```

Then enable SPNEGO in the browser for `http://proxy.demo.local:8081`:

- **Firefox**: `about:config` → `network.negotiate-auth.trusted-uris` →
  add `proxy.demo.local`.
- **Chrome**: launch with
  `--auth-server-whitelist="proxy.demo.local" --auth-negotiate-delegate-allowlist="proxy.demo.local"`.

Opening `http://proxy.demo.local:8081/auth/kibana` then shows no form at
all: either a 401 (no ticket yet) or a redirect straight into Kibana.

`verify.sh` runs the same flow from the `krb5-user` container instead
(same Docker network, resolves the proxy as `proxy` — hence the second
SPN in the keytab, `HTTP/proxy`): `kinit alice`, then
`curl --negotiate -u :` against `/auth/kibana` and the ES relay.

## Networks (F66, F69 — J1-12)

Two Docker networks, the demo's equivalent of a NetworkPolicy (no Helm/K8s
deployment exists yet, F54):

- **`es`** (`internal: true`, no gateway to the outside): `elasticsearch`,
  `proxy`, and the one-shots `setup`, `seed`, `kibana-setup`. They talk to
  `http://elasticsearch:9200` and exit (the one-shots) or stay up (`proxy`).
- **`demo`** (unchanged, host ports): `proxy`, `kibana`, `openldap`,
  `keycloak`, `engine`, `kibana-setup`.

`proxy` is the only durable service on both. `kibana` is **not** on `es`:
the name `elasticsearch` does not resolve for it, and there is no host
port onto Elasticsearch at all — only `127.0.0.1:8081` (the proxy), which
decides `read`/`write`/`cluster_admin` per the ACL before ever forwarding.

Control check: `curl http://127.0.0.1:9200` must refuse the connection;
`scripts/verify.sh` asserts this (step 0).

## Verification

`scripts/verify.sh` covers the F68 criterion, the F66/F69 isolation
check, and the J1-15 ES relay:

0. `127.0.0.1:9200` refuses the connection (Elasticsearch unreachable
   outside `es`)
1. `proxy:8081/health` and `/metrics`
2. LDAPS login alice → `/auth/me` (+ bad password rejected)
3. OIDC smoke: `/auth/login` redirects to Keycloak (302)
4. Kibana login alice, via the product proxy (its only path to
   Elasticsearch)
5. ES relay (run_as, F2): alice reads `equipe-a-sample` through the proxy;
   `equipe-b-sample` is denied (403) by the ACL
6. Kerberos SPNEGO: `401` + `WWW-Authenticate: Negotiate` without a
   ticket, then alice's real ticket (`krb5-user`) through `/auth/kibana`
   and the ES relay

## Ports (`127.0.0.1` only, same as the spike)

| Port  | Service                                     |
|-------|----------------------------------------------|
| 5601  | Kibana                                       |
| 1389  | OpenLDAP (plaintext)                         |
| 1636  | OpenLDAP (LDAPS)                             |
| 18080 | Keycloak                                     |
| 8081  | proxy (product) — only path to Elasticsearch |

Elasticsearch has no host port: it's reachable only from the `es` network
(`proxy` and the one-shot bootstrap/seed jobs).

## Out of scope (see plan)

- Helm (F54).
- Replacing the spike Kibana plugin with the final J2 plugin.
- ACL for `kibana_system` restricted to `.kibana*` and required system
  indices (F67): `kibana_system` is a passthrough account in
  `elasticsearch.passthrough_users` — it relays unchanged, never through
  the ACL.
- Short-lived identity token (F78, J2-03), ES|QL parsing, removing the
  spike.
