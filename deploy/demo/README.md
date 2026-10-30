# proxy-elk demo (J1-13/J1-12, F68/F66/F69)

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

## Two temporary proxy roles

The **product** binary (repo root, `Dockerfile` image, J1-11) does not yet
reverse-proxy Elasticsearch (`run_as`, `_activate`, F2): without that, a
Kibana login cannot go through `cmd/proxy`. Until F2 lands, this demo runs
two proxies side by side — **to be merged** once F2/`run_as` ships in the
product:

- **`gateway`** — built from `spike/proxy` (spike code unchanged, Track A:
  LDAP search-then-bind → `run_as` → `_activate`, SP-06 token). This is the
  demo's **only** Kibana → Elasticsearch path.
- **`proxy`** — **product** `proxy-elk` image (repo root). Exposes
  `/health`, `/metrics`, `/auth/ldap` (LDAPS), `/auth/login` + `/auth/callback`
  (OIDC Keycloak), `/auth/me`. Does not touch Elasticsearch yet.

## Services

| Service         | Role                                                                  |
|-----------------|-----------------------------------------------------------------------|
| `certs`         | Generates the demo LDAPS CA + server cert (one-shot, idempotent)      |
| `elasticsearch` | Single-node cluster, native security enabled, `es` network only (no host port, F66) |
| `setup`         | ES bootstrap: `kibana_system`, `proxy_runas`, users alice/bob/carol   |
| `gateway`       | Spike Track A proxy (Kibana → ES, plaintext LDAP on the internal net) |
| `engine`        | Verifies the signed token (SP-06), separate process from the proxy    |
| `openldap`      | Test directory (alice/bob/carol), plaintext LDAP 389 + LDAPS 636      |
| `keycloak`      | Demo OIDC IdP, realm `demo` imported (client `proxy`, same users)     |
| `kibana`        | Kibana 8.19 + spike_ask plugin (build `spike/kibana`)                 |
| `kibana-setup`  | Per-team Kibana spaces/roles (reuses `spike/scripts/kibana-bootstrap.sh`) |
| `seed`          | Extra demo logs into `equipe-a/b-sample`                              |
| `proxy`         | Product image: `/health`, `/metrics`, `/auth/*`                       |

## LDAP TLS (F5)

`gen-certs.sh` generates a throwaway CA and server certificate under
`certs/` (never committed; see `certs/.gitignore`) before `openldap`
starts. The **product** proxy connects with `ldaps://openldap:636` using
that CA (`configs/proxy.yaml`, `ldap.ca_file`). `gateway` (spike) still
talks plaintext on port 389, on the Docker network only — same as the
spike, accepted for this demo (host exposure limited to `127.0.0.1`).

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

## Networks (F66, F69 — J1-12)

Two Docker networks, the demo's equivalent of a NetworkPolicy (no Helm/K8s
deployment exists yet, F54):

- **`es`** (`internal: true`, no gateway to the outside): `elasticsearch`,
  `gateway`, and the one-shots `setup`, `seed`, `kibana-setup`. They still
  talk to `http://elasticsearch:9200` (spike scripts unchanged) and exit.
- **`demo`** (unchanged, host ports): `gateway`, `kibana`, `proxy`,
  `openldap`, `keycloak`, `engine`, `kibana-setup`.

`gateway` is on both. `kibana` and the product `proxy` are **not** on `es`:
the name `elasticsearch` does not resolve for them, and the host port
`9200` no longer exists at all. Port `9210` (the gateway) remains — that's
access *through* the proxy, not a bypass.

Control check: `curl http://127.0.0.1:9200` must refuse the connection;
`scripts/verify.sh` asserts this (step 0).

## Verification

`scripts/verify.sh` covers the F68 criterion, plus the F66/F69 isolation
check:

0. `127.0.0.1:9200` refuses the connection (Elasticsearch unreachable
   outside `es`)
1. `proxy:8081/health` and `/metrics`
2. LDAPS login alice → `/auth/me` (+ bad password rejected)
3. OIDC smoke: `/auth/login` redirects to Keycloak (302)
4. Kibana login alice via `gateway` (assertions taken from
   [`spike/scripts/verify.sh`](../../spike/scripts/verify.sh))
5. Seeded indices (`equipe-a-sample`, `equipe-b-sample`) present, checked
   through the gateway (`127.0.0.1:9210`), never `9200`

## Ports (`127.0.0.1` only, same as the spike)

| Port  | Service                                     |
|-------|----------------------------------------------|
| 9210  | gateway — only path to Elasticsearch (F66)   |
| 5601  | Kibana                                       |
| 1389  | OpenLDAP (plaintext)                         |
| 1636  | OpenLDAP (LDAPS)                             |
| 18080 | Keycloak                                     |
| 8081  | proxy (product)                              |

Elasticsearch has no host port: it's reachable only from the `es` network
(`gateway` and the one-shot bootstrap/seed jobs).

## Out of scope (see plan)

- Merging `gateway` into the product (F2/`run_as`): later authz/proxy ticket.
- Helm (F54).
- Replacing the spike Kibana plugin with the final J2 plugin.
- ACL for `kibana_system` restricted to `.kibana*` and required system
  indices (F67): needs the product reverse-proxy on the Kibana → ES path,
  not yet the case here (`gateway` is still that path).
