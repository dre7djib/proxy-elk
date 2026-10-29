import type { IRouter, Logger } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';

interface AskRouteDeps {
  engineUrl: string;
  logger: Logger;
}

// Shape of the token returned by the proxy on /_spike/identity-token (see
// spike/proxy/main.go, mintIdentityTokenMiddleware). The plugin neither decrypts
// nor verifies anything itself (F80): it only reads the `token` field to
// relay it to the engine, verbatim.
interface IdentityTokenResponse {
  token: string;
}

interface EngineWhoamiResponse {
  sub?: string;
  groups?: string[];
  aud?: string;
  exp?: number;
  [key: string]: unknown;
}

// registerAskRoute exposes POST /api/spike_ask/ask: this plugin's only
// route (SP-06). It materializes the variant to test first for
// F78-F82 (see the spike plan, after step 6): obtain the short-lived token
// *via Elasticsearch*, with the current user's session, rather than
// through a separate channel.
export function registerAskRoute(router: IRouter, deps: AskRouteDeps): void {
  router.post(
    {
      path: '/api/spike_ask/ask',
      validate: { body: schema.object({}, { unknowns: 'ignore' }) },
      // authRequired: true (default): no Kibana session, no
      // route. Deliberate: alice must be logged in for this spike.
    },
    async (context, request, response) => {
      const core = await context.core;

      // Central point of the spike: asCurrentUser, NOT asInternalUser. The
      // scoped ES client forwards alice's original HTTP request
      // Authorization/cookie to the proxy (F2/F12: neither the plugin nor this
      // code ever sees her password, only what Kibana has
      // already negotiated for her session). Using asInternalUser here would mint
      // a token for kibana_system, not for the user: finding to
      // watch if this guard is ever removed by mistake.
      const esClient = core.elasticsearch.client.asCurrentUser;

      try {
        const tokenResponse = (await esClient.transport.request({
          method: 'POST',
          path: '/_spike/identity-token',
        })) as IdentityTokenResponse;

        if (!tokenResponse?.token) {
          deps.logger.warn('proxy response missing token field on /_spike/identity-token');
          return response.customError({
            statusCode: 502,
            body: { message: 'proxy did not return a token' },
          });
        }

        // Relay unmodified (F80): no key read, no claim
        // rewritten; the engine Authorization header contains nothing
        // other than what the proxy signed.
        const engineResponse = await fetch(`${deps.engineUrl}/whoami`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tokenResponse.token}` },
        });

        const engineBody = (await engineResponse
          .json()
          .catch(() => ({}))) as EngineWhoamiResponse;

        if (!engineResponse.ok) {
          return response.customError({
            statusCode: engineResponse.status,
            body: { message: 'dummy engine: token refused', detail: engineBody },
          });
        }

        return response.ok({ body: engineBody });
      } catch (err) {
        deps.logger.error(`/_spike/identity-token or engine call failed: ${err}`);
        return response.customError({
          statusCode: 502,
          body: { message: 'token-via-Elasticsearch variant failed', detail: `${err}` },
        });
      }
    }
  );
}
