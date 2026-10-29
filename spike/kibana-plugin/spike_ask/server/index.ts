import type { PluginInitializer } from '@kbn/core/server';
import { SpikeAskPlugin } from './plugin';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';
import { configSchema, type SpikeAskConfig } from './config';

export const plugin: PluginInitializer<SpikeAskPluginSetup, SpikeAskPluginStart> = (
  initializerContext
) => new SpikeAskPlugin(initializerContext);

export const config = { schema: configSchema };
export type { SpikeAskConfig };
export type { SpikeAskPluginSetup, SpikeAskPluginStart };
