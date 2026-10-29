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

// Plugin New Platform minimal (SP-06). Un seul rôle : exposer une route
// serveur qui (1) demande un jeton court au proxy avec la session de
// l'utilisateur courant (variante de l'étape 6 du plan du spike), (2) relaie
// ce jeton sans le modifier à un moteur factice (F80), (3) renvoie le
// résultat de vérification du moteur à l'UI.
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
