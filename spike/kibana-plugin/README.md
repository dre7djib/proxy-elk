# `spike_ask` — minimal Kibana plugin of spike SP-06

Plugin source code ([`spike_ask/`](spike_ask/)), to copy into
`kibana/plugins/spike_ask/` of a checkout of the
[elastic/kibana](https://github.com/elastic/kibana) repository at tag `v8.19.23` (same
version as `STACK_VERSION` in [`../.env.example`](../.env.example)), to
be compiled by `pnpm build` from the plugin root and installed in
the Kibana image via `bin/kibana-plugin install`. See
[`../kibana/Dockerfile`](../kibana/Dockerfile) for the full automation
and the runtime finding on the feasibility of this build in the spike
environment.

Deliberately minimal scope (SP-06, F39-F41 + F78-F82):

- a “Spike Ask” application in the left menu ([`public/`](spike_ask/public/)), a button, a `<pre>` that displays the engine’s response;
- a single server route, `POST /api/spike_ask/ask` ([`server/routes/ask.ts`](spike_ask/server/routes/ask.ts)), which:
  1. calls `POST /_spike/identity-token` on Elasticsearch via `context.core.elasticsearch.client.asCurrentUser` (never `asInternalUser`: this is the point that makes the token minted by the proxy carry alice’s identity, not that of `kibana_system`) — this is the “token requested via ES with the user’s session” variant of the spike plan;
  2. relays the received token, without reading or modifying it (F80), to the dummy engine (`POST {engineUrl}/whoami`, `Authorization: Bearer <token>`);
  3. returns the engine’s response (verified identity) or the error to the UI.

No natural-language question, no Discover link, no dependency on `data`/`discover`: that remains the scope of J2-05/J2-06. The plugin holds no signing key (F80): there is neither a private key nor a public key in this folder.
