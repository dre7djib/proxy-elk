import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';

// Application minimale "Spike Ask" (F39, réduit à l'essentiel pour SP-06) :
// un item de menu, une page, un bouton. Pas de question en langage naturel,
// pas de lien Discover (F28, F41 = J2-05/J2-06, hors périmètre).
export class SpikeAskPlugin implements Plugin<SpikeAskPluginSetup, SpikeAskPluginStart> {
  public setup(core: CoreSetup): SpikeAskPluginSetup {
    core.application.register({
      id: 'spikeAsk',
      title: 'Spike Ask',
      async mount(params) {
        const { renderApp } = await import('./application');
        return renderApp(core, params);
      },
    });

    return {};
  }

  public start(_core: CoreStart): SpikeAskPluginStart {
    return {};
  }

  public stop() {}
}
