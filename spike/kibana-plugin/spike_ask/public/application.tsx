import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';

type Step = { esql?: string; index?: string };
type Message = { role: 'user' | 'assistant'; content: string; steps?: Step[]; error?: string };
type Thread = { id: string; title: string; messages: Message[] };

const STORE_KEY = 'spikeAsk.threads';
const MAX_HISTORY = 16;

// Thread state lives in sessionStorage only; J2-14 will move it to an index.
type Action =
  | { type: 'create'; id: string }
  | { type: 'rename'; id: string; title: string }
  | { type: 'delete'; id: string }
  | { type: 'append'; id: string; message: Message }
  | { type: 'patchLast'; id: string; patch: Partial<Message> | ((m: Message) => Partial<Message>) };

export function threadsReducer(threads: Thread[], a: Action): Thread[] {
  switch (a.type) {
    case 'create':
      return [{ id: a.id, title: 'New chat', messages: [] }, ...threads];
    case 'rename':
      return threads.map((t) => (t.id === a.id ? { ...t, title: a.title.trim() || t.title } : t));
    case 'delete':
      return threads.filter((t) => t.id !== a.id);
    case 'append':
      return threads.map((t) => {
        if (t.id !== a.id) return t;
        const title =
          t.messages.length === 0 && a.message.role === 'user'
            ? a.message.content.slice(0, 40)
            : t.title;
        return { ...t, title, messages: [...t.messages, a.message] };
      });
    case 'patchLast':
      return threads.map((t) => {
        if (t.id !== a.id || t.messages.length === 0) return t;
        const last = t.messages[t.messages.length - 1];
        const patch = typeof a.patch === 'function' ? a.patch(last) : a.patch;
        return { ...t, messages: [...t.messages.slice(0, -1), { ...last, ...patch }] };
      });
  }
}

const newId = () => Math.random().toString(36).slice(2);

function loadThreads(): Thread[] {
  try {
    const raw = JSON.parse(sessionStorage.getItem(STORE_KEY) ?? '[]');
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

// Ask page: threads in a sidebar, answers streamed from POST /api/spike_ask/question (SSE).
const SpikeAskApp: React.FC<{ http: CoreSetup['http'] }> = ({ http }) => {
  const [threads, setThreads] = useState<Thread[]>(() => loadThreads());
  const [activeId, setActiveId] = useState<string>(() => loadThreads()[0]?.id ?? '');
  const [question, setQuestion] = useState('');
  const [asking, setAsking] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const threadsRef = useRef(threads);
  threadsRef.current = threads;

  const dispatch = (a: Action) => setThreads((ts) => threadsReducer(ts, a));

  useEffect(() => {
    try {
      sessionStorage.setItem(STORE_KEY, JSON.stringify(threads));
    } catch {
      // storage unavailable: threads live for this page only
    }
  }, [threads]);

  const active = threads.find((t) => t.id === activeId);

  const create = () => {
    const id = newId();
    dispatch({ type: 'create', id });
    setActiveId(id);
  };

  const remove = (id: string) => {
    if (asking && id === activeId) abortRef.current?.abort();
    const rest = threads.filter((t) => t.id !== id);
    dispatch({ type: 'delete', id });
    if (id === activeId) {
      if (rest[0]) setActiveId(rest[0].id);
      else create();
    }
  };

  const rename = (t: Thread) => {
    // shortcut: window.prompt, swap for an inline input when the UI is polished.
    const title = window.prompt('Rename chat', t.title);
    if (title) dispatch({ type: 'rename', id: t.id, title });
  };

  const stop = () => abortRef.current?.abort();

  const send = async () => {
    const text = question.trim();
    if (!text || asking) return;
    let id = activeId;
    if (!id || !active) {
      id = newId();
      dispatch({ type: 'create', id });
      setActiveId(id);
    }
    const history = (threadsRef.current.find((t) => t.id === id)?.messages ?? [])
      .filter((m) => m.content)
      .slice(-MAX_HISTORY)
      .map(({ role, content }) => ({ role, content }));
    dispatch({ type: 'append', id, message: { role: 'user', content: text } });
    dispatch({ type: 'append', id, message: { role: 'assistant', content: '', steps: [] } });
    setQuestion('');
    setAsking(true);
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const res = await http.fetch('/api/spike_ask/question', {
        method: 'POST',
        body: JSON.stringify({ question: text, history }),
        headers: { 'Content-Type': 'application/json' },
        asResponse: true,
        rawResponse: true,
        signal: ac.signal,
      });
      const reader = res.response?.body?.getReader();
      if (!reader) throw new Error('no response stream');
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const blocks = buf.split('\n\n');
        buf = blocks.pop() ?? '';
        for (const blk of blocks) {
          const name = /^event: (.*)$/m.exec(blk)?.[1];
          const data = /^data: (.*)$/m.exec(blk)?.[1];
          if (!name || !data) continue;
          const ev = JSON.parse(data);
          if (name === 'token') {
            dispatch({ type: 'patchLast', id, patch: (m) => ({ content: m.content + ev.text }) });
          } else if (name === 'step') {
            dispatch({ type: 'patchLast', id, patch: (m) => ({ steps: [...(m.steps ?? []), ev] }) });
          } else if (name === 'done') {
            dispatch({
              type: 'patchLast',
              id,
              patch: (m) => ({ content: ev.answer ?? m.content, error: ev.error }),
            });
          } else if (name === 'error') {
            dispatch({ type: 'patchLast', id, patch: { error: ev.error } });
          }
        }
      }
    } catch (err: unknown) {
      // Stop keeps the text already shown; only real failures show an error.
      if (!ac.signal.aborted) {
        dispatch({
          type: 'patchLast',
          id,
          patch: { error: err instanceof Error ? err.message : String(err) },
        });
      }
    } finally {
      setAsking(false);
      abortRef.current = null;
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
      <div style={{ display: 'flex', gap: 16 }}>
        <aside style={{ width: 220, flexShrink: 0 }}>
          <button onClick={create} disabled={asking} style={{ width: '100%' }}>
            + New chat
          </button>
          {threads.map((t) => (
            <div
              key={t.id}
              style={{
                display: 'flex',
                gap: 4,
                padding: '4px 0',
                fontWeight: t.id === activeId ? 'bold' : 'normal',
              }}
            >
              <button
                onClick={() => setActiveId(t.id)}
                disabled={asking}
                style={{ flex: 1, textAlign: 'left', overflow: 'hidden', textOverflow: 'ellipsis' }}
              >
                {t.title}
              </button>
              <button onClick={() => rename(t)} disabled={asking} title="Rename">
                ✎
              </button>
              <button onClick={() => remove(t.id)} title="Delete">
                ✕
              </button>
            </div>
          ))}
        </aside>
        <main style={{ flex: 1, minWidth: 0 }}>
          {(active?.messages ?? []).map((m, i) => (
            <div key={i} style={{ margin: '8px 0' }}>
              <strong>{m.role === 'user' ? 'You' : 'Assistant'}</strong>
              <p style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{m.content}</p>
              {(m.steps ?? []).map((s, j) => (
                <div key={j} style={{ fontSize: 12, color: '#69707d' }}>
                  {s.esql ? `ES|QL: ${s.esql}` : `schema: ${s.index}`}
                </div>
              ))}
              {m.error && <pre style={{ color: 'crimson', whiteSpace: 'pre-wrap' }}>{m.error}</pre>}
            </div>
          ))}
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && send()}
              placeholder="Ask a question"
              style={{ flex: 1 }}
            />
            {asking ? (
              <button onClick={stop}>Stop</button>
            ) : (
              <button onClick={send} disabled={!question.trim()}>
                Ask
              </button>
            )}
          </div>
        </main>
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

export function renderApp(core: CoreSetup, { element }: AppMountParameters) {
  ReactDOM.render(<SpikeAskApp http={core.http} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
}
