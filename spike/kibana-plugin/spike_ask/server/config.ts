import { schema, type TypeOf } from '@kbn/config-schema';

// Minimal spike config: where to reach the dummy engine. No key here
// (F80: the plugin holds no signing secret) — only a
// URL internal to the docker-compose network.
export const configSchema = schema.object({
  engineUrl: schema.string({ defaultValue: 'http://engine:8080' }),
});

export type SpikeAskConfig = TypeOf<typeof configSchema>;
