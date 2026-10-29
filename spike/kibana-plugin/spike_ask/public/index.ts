import type { PluginInitializer } from '@kbn/core/public';
import { SpikeAskPlugin } from './plugin';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';

export const plugin: PluginInitializer<SpikeAskPluginSetup, SpikeAskPluginStart> = () =>
  new SpikeAskPlugin();
