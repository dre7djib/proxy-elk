import type { PluginInitializer } from '@kbn/core/public';
import {
  SpikeSmtpMailPublicPlugin,
  type SpikeSmtpMailPublicSetup,
  type SpikeSmtpMailPublicStart,
} from './plugin';

export const plugin: PluginInitializer<SpikeSmtpMailPublicSetup, SpikeSmtpMailPublicStart> = () =>
  new SpikeSmtpMailPublicPlugin();

export type { SpikeSmtpMailPublicSetup, SpikeSmtpMailPublicStart };
