import type { CoreSetup, CoreStart, Plugin } from '@kbn/core/public';
import type { SpikeAskPluginSetup, SpikeAskPluginStart, SpikeAskSetupDeps } from './types';

// Minimal applications for the spike:
// - Spike Ask: short-lived token → dummy engine
// - Spike Users: create ES shadow user for an existing LDAP uid
export class SpikeAskPlugin implements Plugin<SpikeAskPluginSetup, SpikeAskPluginStart, SpikeAskSetupDeps> {
  public setup(core: CoreSetup, plugins: SpikeAskSetupDeps): SpikeAskPluginSetup {
    core.application.register({
      id: 'spikeAsk',
      title: 'Ask',
      async mount(params) {
        const { renderApp } = await import('./application');
        return renderApp(core, params, plugins.discover.locator);
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
