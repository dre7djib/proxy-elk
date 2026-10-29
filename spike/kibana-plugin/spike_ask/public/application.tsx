import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';

// Single component of the "Spike Ask" page: a button that calls the plugin's
// server route (POST /api/spike_ask/ask) and displays the JSON returned by
// the dummy engine (verified identity: sub, groups, exp) or the error. No
// EUI here on purpose: the spike tests the token path, not the UI.
const SpikeAskApp: React.FC<{ http: CoreSetup['http'] }> = ({ http }) => {
  const [result, setResult] = useState<string>('(not called yet)');
  const [loading, setLoading] = useState(false);

  const callEngine = async () => {
    setLoading(true);
    try {
      const body = await http.post('/api/spike_ask/ask', { body: JSON.stringify({}) });
      setResult(JSON.stringify(body, null, 2));
    } catch (err: unknown) {
      setResult(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 16 }}>
      <h1>Spike Ask (SP-06)</h1>
      <p>
        Calls the dummy engine via the short-lived token issued by the proxy (variant: token requested
        through Elasticsearch, with the current user&apos;s session).
      </p>
      <button onClick={callEngine} disabled={loading}>
        {loading ? 'Calling…' : 'Call the engine'}
      </button>
      <pre style={{ marginTop: 16, background: '#f5f5f5', padding: 12 }}>{result}</pre>
    </div>
  );
};

export function renderApp(core: CoreSetup, { element }: AppMountParameters) {
  ReactDOM.render(<SpikeAskApp http={core.http} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
}
