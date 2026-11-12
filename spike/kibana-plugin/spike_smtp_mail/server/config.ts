import { schema, type TypeOf } from '@kbn/config-schema';

// SMTP settings for the whole Kibana node. Keep secrets out of rule params.
export const configSchema = schema.object({
  smtp: schema.object({
    host: schema.string({ defaultValue: '127.0.0.1' }),
    port: schema.number({ defaultValue: 587 }),
    // true = TLS from connect (typically port 465); false = plain then STARTTLS
    secure: schema.boolean({ defaultValue: false }),
    user: schema.maybe(schema.string()),
    password: schema.maybe(schema.string()),
    from: schema.string({ defaultValue: 'kibana@localhost' }),
  }),
});

export type SpikeSmtpMailConfig = TypeOf<typeof configSchema>;
