import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';

// Minimal "Spike Ask" application (reduced to the essentials for):
// a menu item, a page, a button. No natural-language question,
// no Discover link (= , out of scope).
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
