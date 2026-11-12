// Runtime finding: @kbn/optimizer (entry_point_creator) requires a
// `<plugin>/common` module for any plugin with `ui: true`, even if empty —
// without it, the optimizer fails silently when compiling the public
// bundle ("Module not found: Can't resolve '.../plugins/spike_ask/common'"),
// and `plugin_helpers build` still packs an empty `target/public` into
// the zip without failing the build (finding not to reproduce: check
// the zip's actual contents, not only its exit code).
export const PLUGIN_ID = 'spikeAsk';

// Stub roles created by es-bootstrap.sh / completed by kibana-bootstrap.sh.
// The create-user UI only offers these — LDAP already has the person;
// this page only provisions the ES shadow user + role for run_as.
export const SPIKE_TEAM_ROLES = [
  'equipe_a_viewer',
  'equipe_a_editor',
  'equipe_b_viewer',
] as const;

export type SpikeTeamRole = (typeof SPIKE_TEAM_ROLES)[number];

export function isSpikeTeamRole(value: string): value is SpikeTeamRole {
  return (SPIKE_TEAM_ROLES as readonly string[]).includes(value);
}
