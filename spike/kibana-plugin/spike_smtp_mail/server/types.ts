import type { AlertingServerSetup } from '@kbn/alerting-plugin/server';
import type { FeaturesPluginSetup } from '@kbn/features-plugin/server';

export interface SpikeSmtpMailPluginSetupDeps {
  alerting: AlertingServerSetup;
  features: FeaturesPluginSetup;
}

export type SpikeSmtpMailPluginSetup = Record<string, never>;
export type SpikeSmtpMailPluginStart = Record<string, never>;
