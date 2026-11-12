import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, CoreSetup } from '@kbn/core/public';
import { SPIKE_TEAM_ROLES, type SpikeTeamRole } from '../common';

// Minimal "create ES shadow user" page. The person must already exist in
// LDAP; this form only provisions the native ES account (shadow password
// + team role) and extends proxy_runas. No EUI: same style as Spike Ask.
const SpikeUsersApp: React.FC<{ http: CoreSetup['http'] }> = ({ http }) => {
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<SpikeTeamRole>(SPIKE_TEAM_ROLES[0]);
  const [result, setResult] = useState<string>('(not called yet)');
  const [loading, setLoading] = useState(false);

  const createUser = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    try {
      const body = await http.post('/api/spike_ask/users', {
        body: JSON.stringify({ username, fullName, role }),
      });
      setResult(JSON.stringify(body, null, 2));
    } catch (err: unknown) {
      setResult(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 16, maxWidth: 560 }}>
      <h1>Spike Users</h1>
      <p>
        Create the Elasticsearch <em>shadow</em> user for someone who already exists in LDAP.
        The native password is the shared proxy secret (never typed here). Requires a caller
        with manage-security rights (e.g. <code>elastic</code>); team viewers get 403.
      </p>
      <form onSubmit={createUser} style={{ display: 'grid', gap: 12 }}>
        <label>
          Username (LDAP uid)
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            pattern="[a-z][a-z0-9._-]{0,63}"
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </label>
        <label>
          Full name
          <input
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            required
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </label>
        <label>
          Team role
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as SpikeTeamRole)}
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          >
            {SPIKE_TEAM_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={loading}>
          {loading ? 'Creating…' : 'Create ES shadow user'}
        </button>
      </form>
      <pre style={{ marginTop: 16, background: '#f5f5f5', padding: 12 }}>{result}</pre>
    </div>
  );
};

export function renderUsersApp(core: CoreSetup, { element }: AppMountParameters) {
  ReactDOM.render(<SpikeUsersApp http={core.http} />, element);
  return () => ReactDOM.unmountComponentAtNode(element);
}
