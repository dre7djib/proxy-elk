import type { DiscoverSetup } from '@kbn/discover-plugin/public';

export interface SpikeAskSetupDeps {
  discover: DiscoverSetup;
}
export type SpikeAskPluginSetup = Record<string, never>;
export type SpikeAskPluginStart = Record<string, never>;
