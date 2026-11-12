import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { TriggersAndActionsUIPublicPluginSetup } from '@kbn/triggers-actions-ui-plugin/public';
import { getThresholdEmailRuleType } from './rule_types/threshold_email';

export interface SpikeSmtpMailPublicSetupDeps {
  triggersActionsUi: TriggersAndActionsUIPublicPluginSetup;
}

export type SpikeSmtpMailPublicSetup = Record<string, never>;
export type SpikeSmtpMailPublicStart = Record<string, never>;

/**
 * Registers the rule type form so it appears in
 * Stack Management → Rules → Create rule.
 */
export class SpikeSmtpMailPublicPlugin
  implements
    Plugin<
      SpikeSmtpMailPublicSetup,
      SpikeSmtpMailPublicStart,
      SpikeSmtpMailPublicSetupDeps
    >
{
  public setup(
    _core: CoreSetup,
    { triggersActionsUi }: SpikeSmtpMailPublicSetupDeps
  ): SpikeSmtpMailPublicSetup {
    triggersActionsUi.ruleTypeRegistry.register(getThresholdEmailRuleType());
    return {};
  }

  public start(_core: CoreStart): SpikeSmtpMailPublicStart {
    return {};
  }

  public stop() {}
}
