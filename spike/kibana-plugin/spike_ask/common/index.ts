// Runtime finding (SP-06): @kbn/optimizer (entry_point_creator) requires a
// `<plugin>/common` module for any plugin with `ui: true`, even if empty —
// without it, the optimizer fails silently when compiling the public
// bundle ("Module not found: Can't resolve '.../plugins/spike_ask/common'"),
// and `plugin_helpers build` still packs an empty `target/public` into
// the zip without failing the build (finding not to reproduce: check
// the zip's actual contents, not only its exit code).
export const PLUGIN_ID = 'spikeAsk';
