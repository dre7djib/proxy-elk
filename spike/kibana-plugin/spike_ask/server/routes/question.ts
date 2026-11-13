import type { IRouter, Logger } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';

// POST /api/spike_ask/question: relays a question (or an edited ES|QL query)
// to the proxy's POST /_proxy/ask as the current user. The model key and the
// ES|QL run both live in the proxy; nothing sensitive is held here.
export function registerQuestionRoute(router: IRouter, deps: { logger: Logger }): void {
  router.post(
    {
      path: '/api/spike_ask/question',
      validate: {
        body: schema.object({
          question: schema.maybe(schema.string()),
          esql: schema.maybe(schema.string()),
        }),
      },
    },
    async (context, request, response) => {
      const core = await context.core;
      try {
        const body = await core.elasticsearch.client.asCurrentUser.transport.request({
          method: 'POST',
          path: '/_proxy/ask',
          body: request.body,
        });
        return response.ok({ body: body as Record<string, unknown> });
      } catch (err) {
        deps.logger.error(`/_proxy/ask failed: ${err}`);
        return response.customError({
          statusCode: 502,
          body: { message: 'assistant request failed', attributes: { detail: `${err}` } },
        });
      }
    }
  );
}
