// Contrats de plugin volontairement vides : SP-06 n'expose rien à d'autres
// plugins, c'est un spike autonome (F39-F41 réels = J2-05, hors périmètre).
export type SpikeAskPluginSetup = Record<string, never>;
export type SpikeAskPluginStart = Record<string, never>;
