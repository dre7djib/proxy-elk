# Spike SP-01 to SP-08 — stack 8.19 + OpenLDAP + proxy + LDAP login (run_as) + roles/spaces per team + ES|QL + short-lived token + Basic license

**Throwaway** stack of the technical spike (see [the spike plan](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md)). No tests, no polished architecture: the goal is to remove a precise risk.

**Scope of SP-01**: Elasticsearch + Kibana 8.19 with security enabled, and an OpenLDAP populated with test users. The native login tested here is that of the built-in `elastic` user.

**Scope of SP-02**: a minimal Go proxy ([`proxy/`](proxy/)) now sits between Kibana and Elasticsearch. It is a **transparent passthrough** (no authentication or authorization added) that logs each call as JSON on stdout, to observe what Kibana actually sends to Elasticsearch.

**Scope of SP-03**: the proxy now validates LDAP login (search-then-bind, F4) then talks to Elasticsearch with a service account impersonating the user (`es-security-runas-user`, **Track A**). Alice logs into Kibana with her LDAP password and appears with her own identity and role. **Track A validated by real execution**, with a fix not planned at the start: see [Runtime finding — `_security/profile/_activate`](#runtime-finding--securityprofile_activate-sp-03) below.

**Scope of SP-04**: the built-in ES `viewer`/`editor` roles from SP-03 (access to all spaces) are replaced by a role per team/level pair (`equipe_a_viewer`, `equipe_a_editor`, `equipe_b_viewer`) and a Kibana space per team (`equipe-a`, `equipe-b`). New `kibana-setup` service ([`scripts/kibana-bootstrap.sh`](scripts/kibana-bootstrap.sh)), started after Kibana is reachable, which creates the spaces and completes the roles via Kibana’s roles API (`elasticsearch` + `kibana` privileges, not Elasticsearch’s roles API directly). **Success criterion met by real execution**: alice reads only team A’s space and data, bob modifies a team A dashboard, carol sees nothing of team A — verified via [`scripts/verify.sh`](scripts/verify.sh). Detail in [ES roles and Kibana spaces per team](#es-roles-and-kibana-spaces-per-team-sp-04) below.

**Scope of SP-05**: `FROM`, `LOOKUP JOIN` and `ENRICH` tested via the proxy on 8.19.23, as `elastic` then as `alice` (LDAP path → `run_as`). All three work. Major finding: Elasticsearch’s native ACL protects the **target** index of a `LOOKUP JOIN` just like a `FROM`, but **not** that of an `ENRICH` policy (only a global cluster privilege `monitor_enrich`/`manage_enrich`) — cross-team leak demonstrated. Detail in [SP-05 FROM LOOKUP JOIN and ENRICH via the proxy](#sp-05-from-lookup-join-and-enrich-via-the-proxy) below.

**Scope of SP-06**: short-lived identity token (JWT RS256, F78-F82) between a Kibana plugin and a dummy engine, via a new `engine` service ([`spike/engine/`](engine/)) and a minting route in the proxy (`POST /_spike/identity-token`, [`spike/proxy/main.go`](proxy/main.go)). The variant chosen first by the spike plan — request the token via Elasticsearch, with the user’s session — **works, verified by real execution, end to end, including a Kibana plugin actually compiled and loaded**: the plugin ([`spike/kibana-plugin/`](kibana-plugin/)) calls the proxy via `asCurrentUser`, the proxy issues a token carrying alice’s identity and LDAP groups, and the engine verifies signature, expiration and audience, accepting the good token and rejecting four invalid vectors. Detail in [SP-06 Minimal Kibana plugin + short-lived token](#sp-06-minimal-kibana-plugin--short-lived-token-dummy-engine) below.

**Scope of SP-07**: written finding, no code change. Spaces, roles and `base`/`feature` feature controls hold under the auto-generated **Basic** license; the proxy does not rewrite `GET /_license` or `GET /_xpack`, and a Platinum feature (field-level security) is denied the same way direct and through the proxy. Detail in [SP-07 Kibana license vs proxy](#kibana-license-vs-proxy-sp-07) below.

**Scope of SP-08**: spike closed. Report in [the plan](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md#report-sp-08); requirements F2, F27, F40, F68, F70–F75, F82 updated. **This docker-compose is the base of F68** (J1-13): keep it, do not throw it away.

## Start

```sh
cd spike
cp .env.example .env   # adjust passwords if needed
docker compose up -d
./scripts/verify.sh
```

`verify.sh` waits for the services to respond, then checks:

- that Elasticsearch accepts `elastic` / `ELASTIC_PASSWORD`;
- that the proxy is a transparent passthrough (identical response direct and via the proxy) and that an authenticated search goes through it (SP-02);
- that Kibana accepts that same login via its internal API (`/internal/security/login`), proof of the success criterion “Kibana accepts a native login” — now through the proxy, since Kibana’s `ELASTICSEARCH_HOSTS` points at it;
- that OpenLDAP contains alice, bob, carol and their team groups, and that an LDAP bind with a bad password is denied;
- **(SP-03)** that Elasticsearch authenticates alice as herself (`run_as`) with her role, and rejects a bad LDAP password without ever exposing it to Elasticsearch;
- **(SP-03)** that alice logs into **Kibana** with her LDAP password and appears under her own identity, that a bad password is denied, and that the native `elastic` login has not regressed;
- **(SP-04)** that the `kibana-setup` service finished successfully, that alice only sees space `equipe-a` and its data, that bob can modify a team A dashboard, and that carol sees neither the space nor the data of team A (the ticket’s success criterion).

Then open http://127.0.0.1:5601 in a browser and log in with `alice` / `alicepass`, `bob` / `bobpass` or `carol` / `carolpass` (or `elastic` / the password from `.env`), for a visual confirmation: the space switcher only offers `equipe-a` to alice/bob and `equipe-b` to carol, and the “Dashboard equipe A (SP-04)” dashboard is only visible/editable in space `equipe-a`.

## Access

| Service | URL | Credentials |
| --- | --- | --- |
| Elasticsearch (direct) | http://127.0.0.1:9200 | `elastic` / `ELASTIC_PASSWORD` (see `.env`) |
| Proxy (to Elasticsearch) | http://127.0.0.1:9210 | `elastic` as passthrough, or **any LDAP user** (alice/bob/carol) authenticated via the proxy (SP-03) |
| Kibana (goes through the proxy) | http://127.0.0.1:5601 | `elastic` / `ELASTIC_PASSWORD`, or alice/bob/carol with their LDAP password (SP-03) |
| OpenLDAP | ldap://127.0.0.1:1389 | base `dc=example,dc=org`, admin `cn=admin,dc=example,dc=org` |

LDAP test users (`ldap/01-bootstrap.ldif`), passwords in clear in the LDIF (spike, not a real secret):

| uid | Password | LDAP group | Native ES role (SP-04) | Kibana space |
| --- | --- | --- | --- | --- |
| alice | alicepass | `equipe-a-viewer` | `equipe_a_viewer` (read) | `equipe-a` only |
| bob | bobpass | `equipe-a-editor` | `equipe_a_editor` (Kibana read+write) | `equipe-a` only |
| carol | carolpass | `equipe-b-viewer` | `equipe_b_viewer` (read) | `equipe-b` only |

The LDAP group is not yet mapped automatically to the ES role (groups → team/level mapping, F72): assignment remains static in [`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh), as in SP-03; that comes with the YAML config of J2-01. On the Elasticsearch side, alice/bob/carol have a native password that is **never** the one above (see the SP-03 finding below): only the LDAP password counts for login.

Read account for search-then-bind (F4, SP-03): `cn=readonly,dc=example,dc=org` / `readonlypass` (created by `LDAP_READONLY_USER=true`, not `uid=readonly` as a classic LDIF would have created it).

## Proxy log (SP-02/SP-03)

Each HTTP call that transits through the proxy produces a JSON line on stdout (method, path, request, status, duration, and two flags `security` and `kibana_index`, see SP-02). Since SP-03, four extra fields trace authentication (never the password):

- `auth_scheme`: `passthrough` (service account or `elastic`), `ldap-runas` (authenticated LDAP user, request relayed with `run_as`), `ldap-profile-activate` (fix for `/_security/profile/_activate`, see below), `ldap-denied` (LDAP denied), `basic-invalid`, or `none` (no header).
- `user`: the authenticated user (never the password).
- `run_as`: present only in `ldap-runas`, the identity impersonated towards Elasticsearch.
- `ldap_ms`: duration of search-then-bind (or 0 if served from the 2-minute cache, see `LDAP_CACHE_TTL`).

```sh
docker compose logs -f proxy
docker compose logs proxy | grep '"security":true'       # calls to the ES security API
docker compose logs proxy | grep '"kibana_index":true'    # calls touching .kibana* indices
docker compose logs proxy | grep '"auth_scheme":"ldap-runas"'  # successful LDAP logins (run_as)
```

### Observed security calls

Record taken during a full login + Discover open cycle (1,486 calls logged in total, of which 318 to the security API and 782 to `.kibana*` indices):

| Call | Frequency | Likely role |
| --- | --- | --- |
| `POST /_security/user/_has_privileges` | very frequent (148) | Kibana continuously checks the current user’s rights before displaying each feature |
| `GET /_security/_authenticate` | very frequent (145) | session validation on every UI request (“who am I?”) |
| `GET /_security/profile/<uid>` | frequent (16) | user profile (avatar, display name) |
| `POST /_security/profile/_activate` | rare (2) | user profile activation at login |
| `DELETE /_security/api_key` | rare (5) | cleanup of Kibana internal API keys (e.g. Fleet/ML tasks) |
| `GET /_security/api_key` | rare (1) | reading internal API keys |
| `GET /_security/privilege/kibana-.kibana` | rare (1) | Kibana application privileges on its own index |

**Finding for SP-03/F67**: `_has_privileges` and `_authenticate` are by far the most frequent calls — any identity impersonated via `run_as` will have to answer these two endpoints quickly, otherwise Kibana’s UI becomes perceptibly slower. The rest of the traffic (782 calls) only touches `.kibana*` indices (sessions, saved objects, internal tasks, telemetry): that is exactly the scope F67 must authorize for the `kibana_system` service account, nothing more. The 2-minute LDAP cache (`LDAP_CACHE_TTL`) answers this finding: without it, every `_authenticate`/`_has_privileges` would trigger an LDAP bind.

### Runtime finding — `_security/profile/_activate` (SP-03)

Not planned in the ticket’s initial plan, found by running the spike through rather than stopping at theory: alice’s login systematically failed with 401, while `GET /_security/_authenticate` with `run_as` worked fine.

Cause: just after login, Kibana calls `POST /_security/profile/_activate` to create/activate the user profile (avatar, display name). This call is authenticated with **kibana_system** credentials (so passthrough for the proxy), but carries the password typed by the user in the **JSON body** (`{"grant_type":"password","username":"alice","password":"alicepass"}`), which Elasticsearch verifies **itself** against its native realm — not via the `Authorization` header, so invisible to the proxy’s `run_as` logic. Because alice has no LDAP realm on Elasticsearch (that is the whole point of Track A), her real LDAP password matches nothing on ES, and the request fails before Kibana can even issue a session.

Fix implemented in [`proxy/main.go`](proxy/main.go) (`profileActivateMiddleware`): for this precise endpoint, and only when the grant targets an LDAP user (not a service account), the proxy re-checks the password via LDAP (hot cache in almost every case, since `_authenticate` just ran), then substitutes in the body a shared secret — `NATIVE_SHADOW_PASSWORD` — known only to the proxy and the Elasticsearch bootstrap ([`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh), which uses it as the native password of alice/bob/carol). This secret is **never** typed by a user, never sent to LDAP, never logged.

This fix does not change the principle of Track A (LDAP remains the only source of truth for the password the user types); it fills a precise blind spot of the Kibana + run_as integration, which was not visible in the SP-02 call inventory (2 calls out of 1,486, easy to miss without testing a real end-to-end login).

## ES roles and Kibana spaces per team (SP-04)

Ticket goal: one Elasticsearch role and one Kibana space per team, so that alice (team A, viewer) only reads her team’s data and space, bob (team A, editor) can modify a dashboard of his team, and carol (team B, viewer) sees nothing of team A.

### Why two bootstrap scripts

Kibana privileges (`base: read`/`all`, `spaces`) must be set via **Kibana’s roles API** (`PUT /api/security/role/{name}`), not directly via Elasticsearch `PUT /_security/role`: Kibana registers its own application privileges (`kibana-.kibana`) at startup, and spaces simply do not exist before Kibana is started. The existing `setup` service (SP-01/SP-03) finishes **before** Kibana (it only depends on Elasticsearch): impossible to create spaces or Kibana privileges there.

Two scripts, in order:

1. [`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh) (`setup` service, unchanged in principle): creates three ES **stub** roles (`equipe_a_viewer`, `equipe_a_editor`, `equipe_b_viewer`), with no privileges, just so alice/bob/carol can be assigned to them without an Elasticsearch error. Replaces the built-in `viewer`/`editor` roles of SP-03, which gave access to all spaces.
2. [`scripts/kibana-bootstrap.sh`](scripts/kibana-bootstrap.sh) (new `kibana-setup` service, starts only once Kibana is `healthy`): creates spaces `equipe-a` and `equipe-b` (`POST`/`PUT /api/spaces/space`), then fully rewrites the three stub roles via Kibana’s roles API (`elasticsearch.indices` + `kibana.base`/`spaces`), indexes a test document in `equipe-a-sample` and `equipe-b-sample` (directly on Elasticsearch, to verify isolation of *data* and not only of Kibana objects), and creates a minimal dashboard in space `equipe-a` (`spike-dashboard-equipe-a`).

Between the end of `setup` and the end of `kibana-setup`, alice/bob/carol have a role with no privileges: they can log in but see no space. Short window, judged acceptable for a spike.

Full role definitions (set by `kibana-bootstrap.sh`):

| Role | ES index (`read`) | Kibana space | Kibana base |
| --- | --- | --- | --- |
| `equipe_a_viewer` | `equipe-a-*` | `equipe-a` | `read` |
| `equipe_a_editor` | `equipe-a-*` | `equipe-a` | `all` |
| `equipe_b_viewer` | `equipe-b-*` | `equipe-b` | `read` |

Team A editor and viewer have the **same** index privileges (read): the difference is on Kibana objects in the space (dashboards, etc.), not on the data itself — that is the scope of the success criterion (“bob can modify a dashboard of A”), not a write right on the data.

### Runtime finding — Dev Tools already closed by `base: read` (SP-04)

Before implementing, the identified risk was that a `base: ["read"]` role would leave Dev Tools visible for a viewer (per-sub-feature sub-privileges are a paid feature, so no fine-grained way to hide it). **Tested for real** (`POST /api/console/proxy` with alice’s session): Kibana 8.19 already denies this call with 403 (“this action is granted by the Kibana privileges [console]”) with `base: read` alone, without extra `feature` configuration. No need to customize per-feature privileges for this precise case; also useful for SP-07 (Basic license: the Dev Tools restriction does not come from a paid tier, it is already in the base behavior).

### Verification

[`scripts/verify.sh`](scripts/verify.sh) extends the SP-01 to SP-03 matrix with, once the `kibana-setup` service has finished (checked via `docker compose ps --format '{{.State}}' kibana-setup`):

- alice: `GET /api/spaces/space` contains `equipe-a` and not `equipe-b`; read of A’s dashboard (200); write attempt on that same dashboard denied (403); Dev Tools denied (403); search on `equipe-a-sample` via the proxy (200) and on `equipe-b-sample` denied (403).
- bob: Kibana login succeeds; write succeeds (200) on A’s dashboard.
- carol: `GET /api/spaces/space` contains only `equipe-b`; direct access to space `equipe-a` and its dashboard denied (403 each); search on `equipe-a-sample` via the proxy denied (403), on `equipe-b-sample` succeeds (200).

Executed for real (not only in theory): `docker compose up -d` then `./scripts/verify.sh`, twice in a row (`setup`/`kibana-setup` restarted between the two) to verify that both bootstrap scripts stay idempotent without error.

If a case in this matrix fails, do not start by looking at the proxy: first `GET /_security/_authenticate` via the proxy (is the custom role present?), then `POST /_security/user/_has_privileges`, then the same Kibana call in an `elastic` session to see if the object exists. An unexpected 401 in the proxy log indicates a `run_as` problem; a 403 on Kibana or ES indicates a role or space definition problem, not the proxy.

### Out of scope for SP-04 (planned in J2)

No single-source YAML configuration, no generic/idempotent sync in the sense of F74-F77 (the idempotence tested here is manual, not guaranteed by construction), no `admin` level, no automatic mapping of LDAP groups to team/level (F72), no divergence detection (F76), no dry-run mode (F77). The alice/bob/carol → role assignment remains static in `es-bootstrap.sh`, as in SP-03. That comes in J2-01 (YAML config) and J2-02 (idempotent sync).

## SP-05 FROM LOOKUP JOIN and ENRICH via the proxy

Ticket goal: know which ES|QL commands reference other indices in 8.19, and the minimum Elasticsearch version to retain for F27 (verification of indices read by a query before execution, AI assistant guardrail).

### Why the test indices follow the `equipe-a-*`/`equipe-b-*` pattern

The ticket’s initial plan still assumed alice’s built-in `viewer` role (broad access to all indices). In the meantime, SP-04 replaced it with a role restricted to the `equipe-a-*` pattern (see above). With indices named `sp05-*` as planned, alice would have been able to read none of them: the test via her LDAP identity would have shown nothing about ES|QL itself.

[`scripts/esql-seed.sh`](scripts/esql-seed.sh) therefore creates two index sets, one per team:

| Usage | Team A (readable by alice) | Team B (not readable by alice) |
| --- | --- | --- |
| `FROM` | `equipe-a-sp05-logs` | `equipe-b-sp05-logs` (negative control) |
| `LOOKUP JOIN` (`index.mode: lookup`) | `equipe-a-sp05-hosts` | `equipe-b-sp05-hosts` |
| `ENRICH` (source index + policy) | `equipe-a-sp05-owners` / `sp05-owners-a-policy` | `equipe-b-sp05-owners` / `sp05-owners-b-policy` |

This choice answers F27’s real question: does Elasticsearch natively isolate the **target** index of a `LOOKUP JOIN` or the policy of an `ENRICH`, the same way as `FROM`? Without this cross test, we would only have verified the raw capability of the commands (as `elastic`), not their real security behavior.

### Runtime finding — LOOKUP JOIN requires a `keyword` field

First attempt denied with 400 for **everyone**, including `elastic` (so unrelated to the ACL): `verification_exception`, *"JOIN with right field [host] of type [TEXT] is not supported"*. The join field `host`, left to dynamic mapping, was `text`. Fixed by explicitly mapping `host` (and `owner`) as `keyword` in `esql-seed.sh`.

### Run

```sh
./scripts/esql-seed.sh     # creates the indices and policies above (rerunnable)
./scripts/verify-esql.sh   # plays FROM/LOOKUP JOIN/ENRICH as elastic then as alice
```

`verify-esql.sh` is deliberately not a pass/fail gate like `verify.sh`: some expected results are denials (403), and two cases are marked “open finding” in the output — that is the spike’s real question, not a regression if the result is not the hoped-for one.

### Results

| Command | References an index in the text? | Native ES ACL on the target | Useful minimum 8.x version |
| --- | --- | --- | --- |
| `FROM` | yes (patterns, lists, quoted name) | yes: explicit list with an unauthorized index → `403`; broadened wildcard (`equipe-*-sp05-logs`) → silently filtered to alice’s authorized indices, with no error and no observed leak | GA since 8.14 |
| `LOOKUP JOIN idx ON field` | yes, exact index name required | **yes**: alice denied (400, “Unknown index”) on `LOOKUP JOIN equipe-b-sp05-hosts ON host`, whereas elastic succeeds on the same query | GA in 8.19 (preview in 8.18) |
| `ENRICH policy` | **no**, only a policy name | **no**, see major finding below | GA since the early days of ES\|QL, but insufficient alone for F27 |

### Major runtime finding — ENRICH is not protected by source index

`ENRICH` only requires the **cluster** privilege `monitor_enrich`/`manage_enrich` — confirmed by Elasticsearch’s error message when alice (role `equipe_a_viewer`, without that privilege) tries `ENRICH sp05-owners-a-policy`:

```
action [cluster:monitor/xpack/enrich/esql/resolve_policy] is unauthorized for user [proxy_service]
run as [alice] with effective roles [equipe_a_viewer], this action is granted by the cluster
privileges [cross_cluster_search,monitor_enrich,manage_enrich,monitor,manage,all]
```

Without that privilege, `ENRICH` is denied wholesale, **even for her own team’s policy** (403 on `sp05-owners-a-policy` as well). But the privilege is **cluster-wide**, not per policy or per source index: to test what happens once it is granted, a temporary role was created and attached to alice for the test, then removed:

```sh
curl -u "elastic:${ELASTIC_PASSWORD}" -X PUT http://127.0.0.1:9200/_security/role/sp05_monitor_enrich_test \
  -H 'Content-Type: application/json' \
  -d '{"cluster":["monitor_enrich"],"indices":[{"names":["equipe-a-*"],"privileges":["read","view_index_metadata"]}]}'
curl -u "elastic:${ELASTIC_PASSWORD}" -X PUT http://127.0.0.1:9200/_security/user/alice \
  -H 'Content-Type: application/json' \
  -d '{"roles":["equipe_a_viewer","sp05_monitor_enrich_test"],"full_name":"Alice Martin"}'
```

Result: `FROM equipe-a-sp05-logs | ENRICH sp05-owners-b-policy ON host`, executed by alice via the proxy, returned `"owner": "equipe-b-secret"` — the value from team **B**’s source index, even though alice has no read privilege on `equipe-b-sp05-owners` or `equipe-b-*`. **Cross-team leak confirmed.** Role and assignment removed immediately after the test.

**Direct consequence for F27**: `FROM` and `LOOKUP JOIN` are already protected by Elasticsearch’s native ACL (the target index name is always explicit in the query text); a parser that extracts these names (for audit F49 and fail-closed denial) is enough, with no extra authorization check on the proxy. `ENRICH` needs specific handling: the proxy must resolve `GET /_enrich/policy/<name>` to recover the source index before allowing execution, and deny if the policy is unknown or if the source index is outside the user’s scope (fail-closed, F38) — otherwise granting `monitor_enrich` to a team so it can use `ENRICH` in practice exposes it to every other team’s policies.

**Minimum Elasticsearch version retained**: **8.19** if `LOOKUP JOIN` must be covered by F27 in production (GA at that version, aligned with the choice already made for Kibana 8.19). 8.14 would suffice for `FROM` + `ENRICH` only. No `FORK` in 8.19: only these three commands read other data.

### Out of scope for SP-05

F27 parser (index extraction, ENRICH policy resolution, fail-closed), any change to the proxy (`/_query` already goes through the existing passthrough unchanged, visible in `docker compose logs proxy | grep '"path":"/_query"'`), and the remote cluster (CCS) — the `cluster:index` syntax of `FROM` is documented but not tested with a real remote cluster. Ticket detail in [SP-05](../docs/Tickets%20Proxy%20Elasticsearch/SP-05%20ES-QL%20-%20FROM%2C%20LOOKUP%20JOIN%2C%20ENRICH%20via%20proxy.md).

## SP-06 Minimal Kibana plugin + short-lived token (dummy engine)

Ticket goal: know how a Kibana plugin obtains a short-lived token to pass the user’s identity to an AI engine, and verify that this token carries a verifiable signature, expiration and audience (F78-F82). The spike plan proposed testing first the variant “token requested via Elasticsearch, with the user’s session”, with fallback to an HMAC signed header (F82) if it fails.

### Architecture tested

```
alice → plugin (UI) → Kibana server route → asCurrentUser → proxy (POST /_spike/identity-token) → JWT RS256
                                                                                                        │
                                                        plugin relays the token, without reading or modifying it (F80)
                                                                                                        ▼
                                                                                   dummy engine (POST /whoami)
                                                                                   verifies signature/exp/aud (F79)
```

- The **proxy** ([`proxy/main.go`](proxy/main.go), `mintIdentityTokenMiddleware`) answers itself, never relaying to Elasticsearch, on `POST /_spike/identity-token`: it issues an RS256 JWT (`iss=spike-proxy`, `aud=spike-engine`, `sub=<user>`, `groups=<LDAP groups>`, TTL 5 min) signed with a private key that only it holds ([`keys/README.md`](keys/README.md)).
- The **dummy engine** ([`engine/`](engine/), new `engine` service) holds only the matching **public** key: it verifies the signature method (RS256 only), the signature, expiration (with 60 s clock-skew tolerance) and the audience, then returns the identity carried by the token. No call to Elasticsearch, no AI assistant logic: this is not J2-06/J2-07.
- The **plugin** ([`kibana-plugin/spike_ask/`](kibana-plugin/)) holds no key (F80): its single server route (`POST /api/spike_ask/ask`) calls `/_spike/identity-token` via `context.core.elasticsearch.client.asCurrentUser` (never `asInternalUser`, so the token carries the real user’s identity and not that of `kibana_system`), then relays the received token, verbatim, to the engine.

### Runtime finding — two possible identities behind `asCurrentUser`

The proxy must resolve a user before minting a token, but `asCurrentUser` can carry two forms of authentication depending on the active Kibana provider:

- **Basic LDAP** (the SP-03/SP-04 path): Kibana replays alice’s password on every `asCurrentUser` call, already intercepted by `authMiddleware` (`run_as`). The proxy then knows the identity with no extra call — this is the path **verified by real execution** below.
- **ApiKey/Bearer** (watch point documented before execution): if ever encountered, the proxy introspects `GET /_security/_authenticate` by relaying the original header. This path exists in the code (`auth_scheme: jwt-mint-apikey`) but **was not triggered** in practice with the LDAP flow retained since SP-03: `docker compose logs proxy | grep jwt-mint` only shows `jwt-mint-basic` during the tests.

### Runtime finding — the plugin compiles and loads, contrary to the initial finding

A first attempt had concluded that the plugin could not be compiled in this environment (clone blocked on the network, then hypothesis of a pnpm bootstrap too heavy for the ~4 GB of RAM allocated to the Docker engine, `docker info --format '{{.MemTotal}}'`). **That finding was wrong.** Restarted from scratch, the full build ([`kibana/Dockerfile`](kibana/Dockerfile), which follows Elastic’s official procedure: checkout of the `elastic/kibana` monorepo, `pnpm kbn bootstrap`, then `plugin_helpers build`) succeeds end to end in this same environment, in ~7–10 min. The real blockers were three precise bugs, not a resource limit:

1. `kibana.json` without `owner.name` — required by the Kibana manifest validator;
2. `plugin_helpers build` without `--kibana-version` triggers an interactive prompt (`inquirer`) which crashes for lack of a TTY in `docker build` (`ERR_USE_AFTER_CLOSE: readline was closed`);
3. the internal `buildWebpackPackages` task refuses to run as root (“Kibana should not be run as root”), with no clean `--allow-root` flag exposed by `plugin_helpers build` — fixed by building as the non-root `node` user (already present in the `node:*-bookworm` image) rather than looking for a further workaround.

A fourth fix, on the **proxy** this time (not the Dockerfile), was needed for the plugin’s server route to actually work: the official Elasticsearch client used by `asCurrentUser.transport.request` does a “product check” on every HTTP response and rejects (`ProductNotSupportedError`) anything that does not carry the `X-elastic-product: Elasticsearch` header — including the synthetic 401/403 responses of `POST /_spike/identity-token`, never relayed to a real Elasticsearch. `mintIdentityTokenMiddleware` now sets this header on all its responses (see [`proxy/main.go`](proxy/main.go)).

**Consequence**: `docker-compose.yml` now builds the `kibana` image from [`kibana/Dockerfile`](kibana/Dockerfile) (plugin included) instead of the bare official image, and the ticket’s success criterion (“the plugin loads”) is verified by real execution, not only by a `curl` reproduction of the `asCurrentUser` call.

### Verification

[`scripts/verify-sp06.sh`](scripts/verify-sp06.sh), executed for real against the stack (`docker compose up -d` then the script, like the other SP-0x):

| Case | Result |
| --- | --- |
| Anonymous on `POST /_spike/identity-token` | 401 |
| Service account (`elastic`) on `POST /_spike/identity-token` | 403 (a token represents a user, not a technical account) |
| Alice (Basic LDAP via the proxy) | 200, token received |
| Alice’s token relayed to the engine (`POST /whoami`) | 200, `sub=alice`, `groups=["equipe-a-viewer"]`, `aud=spike-engine` |
| **Plugin route without cookie** (`POST /api/spike_ask/ask`) | **401, not 404: the plugin is loaded** |
| **Plugin route with alice’s Kibana session** (`POST /api/spike_ask/ask`) | **200**, `sub=alice`, `groups=["equipe-a-viewer"]` (via `asCurrentUser` → proxy → engine) |
| Expired token (good key, forged for the test) | 401 “expired token” |
| Wrong audience (good key, forged for the test) | 401 “invalid audience” |
| Bad signature (forged with [`keys/wrong-private.pem`](keys/wrong-private.pem)) | 401 “invalid signature” |
| Positive control (forged token, good claims, good key) | 200 — confirms that the denials above come from the token, not from another problem |

**Ticket success criterion fully met**: signature, expiration, audience all verified by real execution (successes and failures), **and** the Kibana plugin itself loads and serves alice’s real identity end to end.

### Out of scope for SP-06

Real “Ask” page with a natural-language question and Discover link (F39/F41, J2-05/J2-06), signing-key rotation (F81, J2-03), HMAC fallback header (F82, J2-04 — not needed here since the token-via-Elasticsearch variant works). The Kibana license vs proxy is the finding of [SP-07](#kibana-license-vs-proxy-sp-07).

## Kibana license vs proxy (SP-07)

Finding of 2026-10-29, stack actually started (`docker.elastic.co` 8.19.23, `xpack.license.self_generated.type=basic` in [`docker-compose.yml`](docker-compose.yml)). No code modified. This is not a legal opinion.

### What Elastic says

- [Elastic License 2.0](https://github.com/elastic/elasticsearch/blob/main/licenses/ELASTIC-LICENSE-2.0.txt) and [ELv2 FAQ](https://www.elastic.co/licensing/elastic-license/faq): use, modification and redistribution are allowed, with three limits. The second forbids moving, modifying, disabling or circumventing the license-key functionality, and removing or hiding a feature protected by that key.
- [Self-managed subscriptions](https://www.elastic.co/subscriptions), Basic column: role-based access control, file and native authentication, **Kibana Spaces**, **Kibana feature controls**. Paid: Kibana sub-privileges (note 8, sub-feature administration), LDAP/AD/PKI, SSO, Elasticsearch and Kibana audit, field-level and document-level security.
- [Kibana 8.19 privileges](https://www.elastic.co/guide/en/kibana/8.19/kibana-privileges.html): `base`, `feature` and `spaces` are the model used by SP-04; the sub-feature level is described as a subscription feature.

| MVP requirement | Elastic tier | In this spike |
| --- | --- | --- |
| Spaces, roles, `base` read/all (F70–F75) | Basic | Already demonstrated in SP-04 (`verify.sh`: alice only sees `equipe-a`) |
| Hide Dev Tools by sub-privilege | Paid, and unnecessary | SP-04: `base: ["read"]` already denies Dev Tools (403) |
| LDAP/AD/OIDC realm, native audit, FLS/DLS | Paid | Not configured; the proxy’s LDAP does not enable ES’s LDAP realm |

The chosen setup (LDAP in the proxy, native users, `run_as`) uses Basic primitives. It is not Elasticsearch’s LDAP realm without a license. Forging a Platinum license, patching Kibana/ES, or rewriting `/_license` to simulate a higher tier would be an ELv2 circumvention: the proxy does not do that. The proxy code stays Apache-2.0; Kibana and the official image stay under ELv2. Publication of the plugin (compilation against the Kibana monorepo) remains the grey area already noted in the requirements, to settle before a first publication, not here.

### Checks (2026-10-29)

`elastic` password: that of `.env` (`ElasticPass123` in [`.env.example`](.env.example)).

```sh
# Identical bodies, type basic, status active, same uid
curl -s -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200/_license
curl -s -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9210/_license
# GET /_xpack : same bodies (security available, graph/watcher/ml not available)
```

| Check | Result |
| --- | --- |
| `GET /_license` direct (9200) vs proxy (9210) | **identical** JSON: `type=basic`, `status=active`, `uid=0a69a491-63bd-450b-9e02-24993d20cb6a` |
| `GET /_xpack` direct vs proxy | **identical** bodies; `security` available, `graph` / `watcher` / `ml` not |
| Kibana `GET /api/licensing/info` (`elastic` session) | Same uid, `type=basic`, `mode=basic`, `status=active` |
| `GET /_security/_authenticate` as `elastic` | Realm `reserved` direct and via the proxy |
| Same call as `alice` via the proxy | Realm **`default_native`** (SP-03 `run_as`), not an `ldap` realm |
| `GET /api/spaces/space` alice session | `['equipe-a']` only (SP-04 reminder, not fully replayed) |
| `PUT /_security/role/sp07_fls_test` with `field_security` | **identical 403** direct and proxy: `current license is non-compliant for [field and document level security]` |

Nuance, not a bypass: `PUT /api/security/role` accepted (204) then stored `dashboard: ["read","url_create"]` and `discover: ["read","generate_report"]` under this Basic license. Both test roles were deleted immediately. Kibana’s API therefore did not refuse writing these sub-privileges; the spike did not verify whether they are honored in use. That does not change the Platinum denial on the Elasticsearch side (FLS), nor requirement F75: Dev Tools is already closed by `base: read` (SP-04).

**Decision**: F70–F75 (spaces, roles, `base`/`feature` feature controls) stay on the Basic tier. The LDAP proxy + `run_as` does not bypass license verification. **Native** Elastic LDAP, SSO and audit remain paid and out of product.

## Known limitations (accepted for a 0.5 d spike)

- **OpenLDAP image**: `osixia/openldap:1.5.0`, not `bitnami/openldap`. Bitnami withdrew its free images from Docker Hub in 2025 (`docker.io/bitnami/openldap:2.6` not found at the time of the spike, see [bitnami/containers#83267](https://github.com/bitnami/containers/issues/83267)); `osixia/openldap` remains pullable and widely used, but on reduced maintenance. Reassess before J1 (build a custom `slapd` image if needed).
- **No TLS** between Kibana and Elasticsearch, and plaintext LDAP (not LDAPS). Simplifies the transparent proxy of SP-02; to fix before any real use (F5, F68).
- **Single node** Elasticsearch, auto-generated `basic` license (confirmed in SP-07: the proxy does not modify it).
- **No ACL**: any authenticated LDAP user can call any index via the proxy, with the rights of their ES role (per team since SP-04, but static and not derived from a declarative policy). The ACL arrives at milestone J1 (F14).
- **No YAML and no generic sync for roles/spaces**: since SP-04, per-team roles and spaces exist (F70-F75 validated by real execution), but the user → role assignment remains static in `es-bootstrap.sh` (no LDAP groups → team/level mapping, F72), and there is neither a single YAML source, nor divergence detection (F76), nor dry-run mode (F77). That comes in J2-01/J2-02.
- **No login-attempt limiting** (brute force, F8), nor dedicated LDAP timeouts/connection pool (F10): one bind at a time, default timeout of the `go-ldap` client.
- **`go.sum` not committed** ([`proxy/Dockerfile`](proxy/Dockerfile)): `go mod tidy` resolves `github.com/go-ldap/ldap/v3` at image build, which requires network access at `docker compose build` and is not byte-for-byte reproducible. Acceptable for a spike, to fix before J1 (commit `go.sum`, vendoring or a module mirror).
- **Minimal data index**: `equipe-a-sample`/`equipe-b-sample` have only one test document each (SP-04), just to verify isolation per team; not a real dataset.
- **ENRICH not protected by source index (SP-05)**: confirmed by real execution, see [SP-05](#sp-05-from-lookup-join-and-enrich-via-the-proxy). F27 must resolve the policy to its source index before allowing execution; neither the current proxy nor Elasticsearch does this natively.
- **SP-05 test indices not cleaned by `docker compose down -v`**: `equipe-*-sp05-*` and the `sp05-owners-*-policy` policies are created by [`scripts/esql-seed.sh`](scripts/esql-seed.sh) directly on Elasticsearch; they disappear with the `esdata` volume like the rest, but are not recreated automatically by `docker compose up` (rerun `esql-seed.sh` by hand if needed).
- **Slow Kibana plugin build** (~7–10 min): this spike’s `docker-compose.yml` now builds `kibana` from [`kibana/Dockerfile`](kibana/Dockerfile) (plugin [`kibana-plugin/`](kibana-plugin/) included, see the SP-06 finding), which lengthens a `docker compose up --build` compared to the bare official image. Acceptable for a spike; cache it (image registry, CI) before real use.
- **ApiKey/Bearer path of the short-lived token not demonstrated (SP-06)**: the proxy code can introspect `GET /_security/_authenticate` for a user authenticated by ApiKey rather than Basic LDAP, but this path was never triggered in practice (Kibana systematically replays Basic auth with the LDAP flow retained since SP-03); it remains written but not exercised by the real tests.
- **No signing-key rotation (F81)**: a single RSA key pair for the whole spike ([`keys/`](keys/)). Rotation without service interruption is the scope of J2-03.

## Stop / clean up

```sh
docker compose down -v   # also deletes the volumes (ES, Kibana, LDAP data)
```
