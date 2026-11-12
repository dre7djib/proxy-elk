import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { SpikeAskPluginSetup, SpikeAskPluginStart } from './types';

// Minimal applications for the spike:
// - Spike Ask: short-lived token → dummy engine
// - Spike Users: create ES shadow user for an existing LDAP uid
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

    core.application.register({
      id: 'spikeUsers',
      title: 'Spike Users',
      async mount(params) {
        const { renderUsersApp } = await import('./users_application');
        return renderUsersApp(core, params);
      },
    });

    return {};
  }

  public start(_core: CoreStart): SpikeAskPluginStart {
    return {};
  }

  public stop() {}
}
