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
import { registerUsersRoute } from './routes/users';

// Minimal New Platform plugin. Routes:
// (1) short-lived token → dummy engine (Ask page)
// (2) create ES shadow user for an existing LDAP uid (Users page)
export class SpikeAskPlugin implements Plugin<SpikeAskPluginSetup, SpikeAskPluginStart> {
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext<SpikeAskConfig>) {
    this.logger = this.initializerContext.logger.get();
  }

  public setup(core: CoreSetup): SpikeAskPluginSetup {
    const config = this.initializerContext.config.get<SpikeAskConfig>();
    const router = core.http.createRouter();

    registerAskRoute(router, { engineUrl: config.engineUrl, logger: this.logger });
    registerUsersRoute(router, {
      shadowPassword: config.shadowPassword,
      logger: this.logger,
    });

    return {};
  }

  public start(_core: CoreStart): SpikeAskPluginStart {
    return {};
  }

  public stop() {}
}
