import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';

// Minimal "Spike Ask" application (F39, reduced to the essentials for SP-06):
// a menu item, a page, a button. No natural-language question,
// no Discover link (F28, F41 = J2-05/J2-06, out of scope).
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
