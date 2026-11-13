import { schema, type TypeOf } from '@kbn/config-schema';

// Minimal spike config: where to reach the dummy engine, plus the
// shared native shadow password used when creating ES users that
// already exist in LDAP (see routes/users.ts). No signing key here.
export const configSchema = schema.object({
  engineUrl: schema.string({ defaultValue: 'http://engine:8080' }),
  // Same secret as NATIVE_SHADOW_PASSWORD / elasticsearch.shadow_password:
  // never typed by the end user, never shown in the UI. Pass via
  // SPIKEASK_SHADOWPASSWORD in docker-compose (kibana-docker env convention).
  // Proxy route minting the identity token (J2-03). The spike compose overrides
  // it via SPIKEASK_TOKENPATH to the old spike proxy path.
  tokenPath: schema.string({ defaultValue: '/_proxy/identity-token' }),
  shadowPassword: schema.string({ defaultValue: '' }),
});

export type SpikeAskConfig = TypeOf<typeof configSchema>;
