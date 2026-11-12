# Kibana plugins of the spike

## `spike_ask` — short-lived token → dummy engine

Plugin source code ([`spike_ask/`](spike_ask/)), to copy into
`kibana/plugins/spike_ask/` of a checkout of the
[elastic/kibana](https://github.com/elastic/kibana) repository at tag `v8.19.23` (same
version as `STACK_VERSION` in [`../.env.example`](../.env.example)), to
be compiled by `pnpm build` from the plugin root and installed in
the Kibana image via `bin/kibana-plugin install`. See
[`../kibana/Dockerfile`](../kibana/Dockerfile) for the full automation
and the runtime finding on the feasibility of this build in the spike
environment.

## `spike_smtp_mail` — SMTP on Basic without Connectors

Separate sketch ([`spike_smtp_mail/`](spike_smtp_mail/)): an Alerting **rule
type** with `minimumLicenseRequired: 'basic'` whose executor sends mail over
SMTP directly. It does **not** register an Actions connector (that path is
hard-gated to Gold+ for third parties). The public side registers the form with
`triggersActionsUi` so you create the rule in **Stack Management → Rules**
(not only via API). See its [README](spike_smtp_mail/README.md).
Not wired into the compose image yet — copy/build like `spike_ask` when you
want to try it.

Deliberately minimal scope (+):

- a “Spike Ask” application in the left menu ([`public/`](spike_ask/public/)), a button, a `<pre>` that displays the engine’s response;
- a “Spike Users” application ([`public/users_application.tsx`](spike_ask/public/users_application.tsx)): form to create the Elasticsearch *shadow* user for an LDAP uid that already exists (username, full name, team role). The native password is never typed in the UI — it comes from `spikeAsk.shadowPassword` (`SPIKEASK_SHADOWPASSWORD` in compose, same secret as `NATIVE_SHADOW_PASSWORD`);
- server routes:
  - `POST /api/spike_ask/ask` ([`server/routes/ask.ts`](spike_ask/server/routes/ask.ts)):
    1. calls `POST /_spike/identity-token` on Elasticsearch via `context.core.elasticsearch.client.asCurrentUser` (never `asInternalUser`: this is the point that makes the token minted by the proxy carry alice’s identity, not that of `kibana_system`) — this is the “token requested via ES with the user’s session” variant of the spike plan;
    2. relays the received token, without reading or modifying it, to the dummy engine (`POST {engineUrl}/whoami`, `Authorization: Bearer <token>`);
    3. returns the engine’s response (verified identity) or the error to the UI.
  - `POST /api/spike_ask/users` ([`server/routes/users.ts`](spike_ask/server/routes/users.ts)): `PUT /_security/user/<uid>` with the shadow password + role via `asCurrentUser`, then extends `proxy_runas.run_as` so the proxy can impersonate the new user. Callers without manage-security (e.g. alice) get 403. Verify with [`../scripts/verify-create-user.sh`](../scripts/verify-create-user.sh) (LDAP-only `dave`).

No natural-language question, no Discover link, no dependency on `data`/`discover`: that remains later work. The plugin holds no signing key: there is neither a private key nor a public key in this folder.
