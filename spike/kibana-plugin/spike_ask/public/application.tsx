import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';
import type { DiscoverSetup } from '@kbn/discover-plugin/public';

type Locator = DiscoverSetup['locator'];

// Single component of the "Spike Ask" page: a button that calls the plugin's
// server route (POST /api/spike_ask/ask) and displays the JSON returned by
// the dummy engine (verified identity: sub, groups, exp) or the error. No
// EUI here on purpose: the spike tests the token path, not the UI.
const SpikeAskApp: React.FC<{ http: CoreSetup['http']; locator: Locator }> = ({
  http,
  locator,
}) => {
  const [esql, setEsql] = useState('FROM logs-* | LIMIT 10');
  const [from, setFrom] = useState('now-15m');
  const [to, setTo] = useState('now');

  // The locator builds the URL (incl. the /s/<space> prefix); no hand-made hash.
  const openInDiscover = async () => {
    const url = await locator?.getUrl({ query: { esql }, timeRange: { from, to } });
    if (url) window.open(url, '_blank');
  };

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
      <h1>Ask</h1>
      <label>
        ES|QL query
        <textarea value={esql} onChange={(e) => setEsql(e.target.value)} rows={3} style={{ display: 'block', width: '100%' }} />
      </label>
      <label>
        From <input value={from} onChange={(e) => setFrom(e.target.value)} />
      </label>{' '}
      <label>
        To <input value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <div style={{ margin: '8px 0' }}>
        <button onClick={openInDiscover} disabled={!esql.trim() || !locator}>
          Open in Discover
        </button>
      </div>
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

export function renderApp(core: CoreSetup, { element }: AppMountParameters, locator: Locator) {
  ReactDOM.render(<SpikeAskApp http={core.http} locator={locator} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
}
