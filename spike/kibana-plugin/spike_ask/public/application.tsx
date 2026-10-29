import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';

// Composant unique de la page "Spike Ask" : un bouton qui appelle la route
// serveur du plugin (POST /api/spike_ask/ask) et affiche le JSON renvoyé par
// le moteur factice (identité vérifiée : sub, groups, exp) ou l'erreur. Pas
// d'EUI ici volontairement : le spike teste le chemin du jeton, pas l'UI.
const SpikeAskApp: React.FC<{ http: CoreSetup['http'] }> = ({ http }) => {
  const [result, setResult] = useState<string>('(pas encore appelé)');
  const [loading, setLoading] = useState(false);

  const callEngine = async () => {
    setLoading(true);
    try {
      const body = await http.post('/api/spike_ask/ask', { body: JSON.stringify({}) });
      setResult(JSON.stringify(body, null, 2));
    } catch (err: unknown) {
      setResult(`Erreur: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 16 }}>
      <h1>Spike Ask (SP-06)</h1>
      <p>
        Appelle le moteur factice via le jeton court émis par le proxy (variante : jeton demandé à
        travers Elasticsearch, avec la session de l&apos;utilisateur courant).
      </p>
      <button onClick={callEngine} disabled={loading}>
        {loading ? 'Appel en cours…' : 'Appeler le moteur'}
      </button>
      <pre style={{ marginTop: 16, background: '#f5f5f5', padding: 12 }}>{result}</pre>
    </div>
  );
};

export function renderApp(core: CoreSetup, { element }: AppMountParameters) {
  ReactDOM.render(<SpikeAskApp http={core.http} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
}
