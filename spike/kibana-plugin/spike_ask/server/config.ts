import { schema, type TypeOf } from '@kbn/config-schema';

// Config minimale du spike : où joindre le moteur factice. Pas de clé ici
// (F80 : le plugin ne détient aucun secret de signature) — seulement une
// URL interne au réseau docker-compose.
export const configSchema = schema.object({
  engineUrl: schema.string({ defaultValue: 'http://engine:8080' }),
});

export type SpikeAskConfig = TypeOf<typeof configSchema>;
