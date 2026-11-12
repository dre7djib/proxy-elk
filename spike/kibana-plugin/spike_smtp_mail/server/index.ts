import type { PluginInitializer } from '@kbn/core/server';
import { SpikeSmtpMailPlugin } from './plugin';
import type { SpikeSmtpMailPluginSetup, SpikeSmtpMailPluginStart } from './types';
import { configSchema, type SpikeSmtpMailConfig } from './config';

export const plugin: PluginInitializer<SpikeSmtpMailPluginSetup, SpikeSmtpMailPluginStart> = (
  initializerContext
) => new SpikeSmtpMailPlugin(initializerContext);

export const config = { schema: configSchema };
export type { SpikeSmtpMailConfig };
export type { SpikeSmtpMailPluginSetup, SpikeSmtpMailPluginStart };
