// Constat d'exécution (SP-06) : @kbn/optimizer (entry_point_creator) exige un
// module `<plugin>/common` pour tout plugin avec `ui: true`, même vide —
// sans lui, l'optimiseur échoue silencieusement à la compilation du bundle
// public ("Module not found: Can't resolve '.../plugins/spike_ask/common'"),
// et `plugin_helpers build` emballe quand même un `target/public` vide dans
// le zip sans faire échouer le build (constat à ne pas reproduire : vérifier
// le contenu réel du zip, pas seulement son code de sortie).
export const PLUGIN_ID = 'spikeAsk';
