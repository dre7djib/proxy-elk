import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';

type Step = {
  esql?: string;
  columns?: Array<{ name: string }>;
  values?: unknown[][];
};

// Ask page: a question goes to POST /api/spike_ask/question. The proxy runs
// the tool loop and returns a natural-language answer plus the queries used.
const SpikeAskApp: React.FC<{ http: CoreSetup['http'] }> = ({ http }) => {
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [steps, setSteps] = useState<Step[]>([]);
  const [askError, setAskError] = useState('');
  const [asking, setAsking] = useState(false);

  const send = async () => {
    setAsking(true);
    setAskError('');
    setAnswer('');
    setSteps([]);
    try {
      const res = await http.post<{
        answer?: string;
        steps?: Step[];
        error?: string;
      }>('/api/spike_ask/question', { body: JSON.stringify({ question }) });
      setAnswer(res.answer ?? '');
      setSteps(res.steps ?? []);
      setAskError(res.error ?? '');
    } catch (err: unknown) {
      setAskError(err instanceof Error ? err.message : String(err));
    } finally {
      setAsking(false);
    }
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
        Question
        <input value={question} onChange={(e) => setQuestion(e.target.value)} style={{ display: 'block', width: '100%' }} />
      </label>
      <div style={{ margin: '8px 0' }}>
        <button onClick={send} disabled={asking || !question.trim()}>
          {asking ? 'Working…' : 'Ask'}
        </button>
      </div>
      {answer && <p>{answer}</p>}
      {askError && <pre style={{ color: 'crimson', whiteSpace: 'pre-wrap' }}>{askError}</pre>}
      {steps.map((step, i) => (
        <details key={i}>
          <summary>Query {i + 1}</summary>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{step.esql}</pre>
          {step.columns && step.columns.length > 0 && (
            <table border={1} cellPadding={4} style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {step.columns.map((c) => (
                    <th key={c.name}>{c.name}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(step.values ?? []).map((row, ri) => (
                  <tr key={ri}>
                    {row.map((v, j) => (
                      <td key={j}>{v === null ? '' : String(v)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </details>
      ))}
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
