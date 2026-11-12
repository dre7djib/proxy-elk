import type {
  CoreSetup,
  CoreStart,
  Plugin,
  PluginInitializerContext,
  Logger,
} from '@kbn/core/server';
import type { SpikeSmtpMailConfig } from './config';
import type {
  SpikeSmtpMailPluginSetup,
  SpikeSmtpMailPluginSetupDeps,
  SpikeSmtpMailPluginStart,
} from './types';
import { registerThresholdEmailRuleType } from './rule_types/threshold_email';
import { RULE_TYPE_ID, PLUGIN_ID } from '../common';

/**
 * Registers a Basic-license Alerting rule type whose executor sends SMTP
 * mail directly. Does not call actions.registerType (Connectors).
 */
export class SpikeSmtpMailPlugin
  implements Plugin<
    SpikeSmtpMailPluginSetup,
    SpikeSmtpMailPluginStart,
    SpikeSmtpMailPluginSetupDeps
  >
{
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext<SpikeSmtpMailConfig>) {
    this.logger = this.initializerContext.logger.get();
  }

  public setup(_core: CoreSetup, plugins: SpikeSmtpMailPluginSetupDeps): SpikeSmtpMailPluginSetup {
    const config = this.initializerContext.config.get<SpikeSmtpMailConfig>();

    registerThresholdEmailRuleType(plugins.alerting, {
      config,
      logger: this.logger,
    });

    // Privilege mapping so the rule type is creatable in the Rules UI
    // for users who have this feature (and for elastic / kibana_admin).
    plugins.features.registerKibanaFeature({
      id: PLUGIN_ID,
      name: 'Spike SMTP mail (Basic)',
      category: { id: 'management', label: 'Management' },
      app: [],
      alerting: [RULE_TYPE_ID],
      privileges: {
        all: {
          app: [],
          api: [],
          savedObject: { all: [], read: [] },
          ui: [],
          alerting: {
            rule: { all: [RULE_TYPE_ID] },
            alert: { all: [RULE_TYPE_ID] },
          },
        },
        read: {
          app: [],
          api: [],
          savedObject: { all: [], read: [] },
          ui: [],
          alerting: {
            rule: { read: [RULE_TYPE_ID] },
            alert: { read: [RULE_TYPE_ID] },
          },
        },
      },
    });

    this.logger.info(
      `spikeSmtpMail: registered rule type ${RULE_TYPE_ID} (Basic, SMTP outside Connectors)`
    );

    return {};
  }

  public start(_core: CoreStart): SpikeSmtpMailPluginStart {
    return {};
  }

  public stop() {}
}
