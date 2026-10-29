import type {
  CoreSetup,
  CoreStart,
  Plugin,
  PluginInitializerContext,
  Logger,
} from '@kbn/core/server';
import type { SpikeAskConfig } from './config';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';
import { registerAskRoute } from './routes/ask';

// Minimal New Platform plugin (SP-06). Single role: expose a server
// route that (1) requests a short-lived token from the proxy with the current
// user's session (variant from step 6 of the spike plan), (2) relays
// that token unmodified to a dummy engine (F80), (3) returns the
// engine's verification result to the UI.
export class SpikeAskPlugin implements Plugin<SpikeAskPluginSetup, SpikeAskPluginStart> {
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext<SpikeAskConfig>) {
    this.logger = this.initializerContext.logger.get();
  }

  public setup(core: CoreSetup): SpikeAskPluginSetup {
    const config = this.initializerContext.config.get<SpikeAskConfig>();
    const router = core.http.createRouter();

    registerAskRoute(router, { engineUrl: config.engineUrl, logger: this.logger });

    return {};
  }

  public start(_core: CoreStart): SpikeAskPluginStart {
    return {};
  }

  public stop() {}
}
