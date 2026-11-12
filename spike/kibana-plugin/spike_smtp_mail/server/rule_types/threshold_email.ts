import { schema } from '@kbn/config-schema';
import type { Logger } from '@kbn/core/server';
import type { AlertingServerSetup } from '@kbn/alerting-plugin/server';
import { RULE_TYPE_ID } from '../../common';
import type { SpikeSmtpMailConfig } from '../config';
import { sendSmtpMail } from '../lib/smtp_send';

const paramsSchema = schema.object({
  // Comma-separated list also accepted as a single string
  to: schema.string({ minLength: 1 }),
  subject: schema.string({ minLength: 1 }),
  body: schema.string({ defaultValue: 'Alert fired.' }),
  // Optional: only send when this index has at least `minDocCount` hits
  index: schema.maybe(schema.string()),
  minDocCount: schema.number({ defaultValue: 1, min: 0 }),
  // Simple query string; default match_all when index is set
  query: schema.string({ defaultValue: '*' }),
});

export type ThresholdEmailParams = {
  to: string;
  subject: string;
  body: string;
  index?: string;
  minDocCount: number;
  query: string;
};

/**
 * Basic-license rule type. Mail is sent inside the executor (SMTP),
 * not via actions.registerType / Connectors.
 */
export function registerThresholdEmailRuleType(
  alerting: AlertingServerSetup,
  deps: { config: SpikeSmtpMailConfig; logger: Logger }
): void {
  alerting.registerType({
    id: RULE_TYPE_ID,
    name: 'SMTP mail (Basic)',
    category: 'management',
    producer: 'spikeSmtpMail',
    solution: 'stack',
    minimumLicenseRequired: 'basic',
    isExportable: true,
    defaultScheduleInterval: '1m',
    actionGroups: [{ id: 'default', name: 'Mail sent' }],
    defaultActionGroupId: 'default',
    // No Connectors required: leave actionVariables empty; optional Index/Server log
    // connectors can still be attached later if the operator wants them.
    validate: {
      params: {
        validate: (object: unknown) => paramsSchema.validate(object),
      },
    },
    async executor(options) {
      const { services, params, logger: ruleLogger } = options;
      const log = ruleLogger ?? deps.logger;
      const p = params as ThresholdEmailParams;

      let shouldSend = true;
      let hitCount = 0;

      if (p.index) {
        const result = await services.scopedClusterClient.asCurrentUser.search({
          index: p.index,
          size: 0,
          query: {
            query_string: { query: p.query || '*' },
          },
          track_total_hits: true,
        });
        const total = result.hits.total;
        hitCount = typeof total === 'number' ? total : total?.value ?? 0;
        shouldSend = hitCount >= p.minDocCount;
        log.debug(
          `spikeSmtpMail: index=${p.index} hits=${hitCount} threshold=${p.minDocCount} send=${shouldSend}`
        );
      }

      if (!shouldSend) {
        return { state: {} };
      }

      const recipients = p.to
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const text = [
        p.body,
        '',
        p.index ? `Index: ${p.index}` : null,
        p.index ? `Hits: ${hitCount} (min ${p.minDocCount})` : null,
        `Query: ${p.query}`,
        `At: ${options.startedAt.toISOString()}`,
      ]
        .filter(Boolean)
        .join('\n');

      try {
        await sendSmtpMail(deps.config.smtp, {
          to: recipients,
          subject: p.subject,
          text,
        });
        log.info(`spikeSmtpMail: sent to ${recipients.join(', ')}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log.error(`spikeSmtpMail: SMTP send failed: ${message}`);
        throw err;
      }

      // Optional Kibana alert instance (UI / history). Attached Connectors
      // (Index / Server log only on Basic) would run from here if configured.
      const alert = services.alertFactory.create('smtp-sent');
      alert.scheduleActions('default', {
        subject: p.subject,
        to: recipients.join(', '),
        hitCount,
      });

      return { state: {} };
    },
  });
}
