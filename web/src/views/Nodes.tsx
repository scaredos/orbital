import { useContext, useState } from 'react';
import { ago, api, can, SearchCtx, useMe, usePoll, type Approval, type Node, type Session } from '../api';
import { Icon, Labels } from '../ui';

export function Nodes() {
  const me = useMe();
  const search = useContext(SearchCtx).toLowerCase();
  const [nodes, error, reload] = usePoll<Node[]>('/v1/nodes', 10000);
  const [sessions] = usePoll<Session[]>(can(me, 'audit:read') ? '/v1/sessions' : null, 10000);
  const [approvals] = usePoll<Approval[]>(can(me, 'approvals:decide') ? '/v1/approvals' : null, 10000);
  const [filter, setFilter] = useState('all');

  const list = nodes ?? [];
  const envs = [...new Set(list.map(n => n.labels.env).filter(Boolean))].sort();
  const shown = list.filter(n =>
    (filter === 'all' || (filter === 'offline' ? !n.online : n.labels.env === filter)) &&
    (!search || [n.name, ...Object.entries(n.labels).map(([k, v]) => `${k}=${v}`), ...Object.keys(n.services)].some(s => s.toLowerCase().includes(search))));
  const live = sessions?.filter(s => !s.ended_at) ?? [];
  const today = sessions?.filter(s => s.recording_sha256 && new Date(s.started_at).toDateString() === new Date().toDateString()) ?? [];
  const pending = approvals?.filter(a => a.status === 'pending') ?? [];
  const online = list.filter(n => n.online).length;

  const remove = async (name: string) => {
    if (!confirm(`Remove ${name}? Its agent certificate is revoked and live sessions end.`)) return;
    try { await api(`/v1/nodes/${encodeURIComponent(name)}`, 'DELETE'); reload(); } catch (e) { alert((e as Error).message); }
  };

  return (
    <>
      <div className="head rise">
        <div><h1>Nodes</h1><p className="sub">Hosts connected to this orchestrator through outbound mTLS tunnels.</p></div>
        <div className="flex-1" />
        {can(me, 'nodes:write') && <a className="btn primary" href="#add-node"><Icon name="plus" />Add node</a>}
      </div>
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4 mb-4">
        <Stat i={1} k="Nodes online" v={<>{online}<span className="small"> / {list.length}</span></>} d={`${list.length - online} offline`} />
        <Stat i={2} k="Active sessions" v={sessions ? live.length : '—'} d={sessions ? `${live.filter(s => s.emergency).length} break-glass` : 'needs audit:read'} />
        <Stat i={3} k="Pending approvals" v={approvals ? <span style={{ color: pending.length ? 'var(--warn)' : undefined }}>{pending.length}</span> : '—'}
          d={approvals ? `${approvals.filter(a => a.emergency).length} break-glass to review` : 'needs approvals:decide'} />
        <Stat i={4} k="Recorded today" v={sessions ? today.length : '—'} d="SSH sessions with a recording" />
      </div>
      <div className="card rise" style={{ '--i': 5 } as React.CSSProperties}>
        <div className="row pad" style={{ paddingBottom: 0 }}>
          <div className="seg" role="group" aria-label="Filter nodes">
            {[['all', 'All'], ...envs.map(e => [e, `env=${e}`]), ['offline', 'Offline']].map(([v, t]) => (
              <button key={v} aria-pressed={filter === v} onClick={() => setFilter(v)}>{t}</button>
            ))}
          </div>
          {error && <span className="small" style={{ color: 'var(--bad)' }}>{error}</span>}
        </div>
        <div className="tablewrap mt-2">
          <table className="t">
            <thead><tr><th>Node</th><th>Labels</th><th>Services</th><th>Agent</th><th>Last seen</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {shown.map(n => (
                <tr key={n.name}>
                  <td>
                    <div className="row"><span className={`dot ${n.online ? 'ok' : n.stale ? 'bad' : 'warn'}`} aria-label={n.online ? 'online' : 'offline'} /><span className="name">{n.name}</span></div>
                    <div className="small mono">cert until {new Date(n.cert_expires_at).toLocaleDateString()}</div>
                  </td>
                  <td><Labels labels={n.labels} /></td>
                  <td><div className="row">{Object.entries(n.services).map(([s, p]) => <span key={s} className={`chip ${n.online ? 'acc' : ''}`}>{s} :{p}</span>)}</div></td>
                  <td className="small">{n.version ?? '—'}{n.stale && <> · <span className="chip bad">stale</span></>}</td>
                  <td className="small" style={{ color: n.online ? undefined : 'var(--bad)' }}>{ago(n.last_seen)}</td>
                  <td>
                    <div className="row" style={{ flexWrap: 'nowrap' }}>
                      {n.online ? <a className="btn sm" href={`#request/${encodeURIComponent(n.name)}`}>Connect</a> : <button className="btn sm" disabled>Offline</button>}
                      {can(me, 'nodes:write') && <button className="btn sm danger" onClick={() => remove(n.name)} aria-label={`Remove ${n.name}`}>Remove</button>}
                    </div>
                  </td>
                </tr>
              ))}
              {nodes && !shown.length && <tr><td colSpan={6} className="small text-center">{list.length ? 'No nodes match.' : 'No nodes yet. Add one to get started.'}</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

function Stat({ i, k, v, d }: { i: number; k: string; v: React.ReactNode; d: string }) {
  return (
    <div className="card pad stat rise" style={{ '--i': i } as React.CSSProperties}>
      <div className="k">{k}</div><div className="v">{v}</div><div className="d">{d}</div>
    </div>
  );
}
