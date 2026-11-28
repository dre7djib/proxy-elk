import type { IRouter, Logger } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';
import type { Readable } from 'stream';

// POST /api/spike_ask/question: relays a question to the proxy's POST /_proxy/ask
// as the current user and pipes the SSE answer through without buffering.
// The model key and the tool loop both live in the proxy.
export function registerQuestionRoute(router: IRouter, deps: { logger: Logger }): void {
  router.post(
    {
      path: '/api/spike_ask/question',
      validate: {
        body: schema.object({
          question: schema.maybe(schema.string()),
          history: schema.maybe(
            schema.arrayOf(
              schema.object({ role: schema.string(), content: schema.string() }),
              { maxSize: 16 }
            )
          ),
        }),
      },
    },
    async (context, request, response) => {
      const core = await context.core;
      try {
        const stream = (await core.elasticsearch.client.asCurrentUser.transport.request(
          {
            method: 'POST',
            path: '/_proxy/ask',
            body: request.body,
          },
          { asStream: true, headers: { Accept: 'text/event-stream' } }
        )) as Readable;
        // Stop in the browser aborts the request: cut the upstream so the proxy cancels the loop.
        request.events.aborted$.subscribe(() => stream.destroy());
        return response.ok({
          body: stream,
          headers: {
            'content-type': 'text/event-stream',
            'cache-control': 'no-cache',
            'x-accel-buffering': 'no',
          },
        });
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
