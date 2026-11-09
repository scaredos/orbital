import { useState } from 'react';
import { api, can, clock, useMe, usePoll, type AuditEvent, type Session } from '../api';
import { Seg } from '../ui';
import { Replay } from './Terminal';

type Filter = 'all' | 'ssh' | 'web' | 'sftp' | 'live' | 'emergency';

export function Audit({ session: selected }: { session?: string }) {
  const me = useMe();
  const [tab, setTab] = useState<'sessions' | 'events'>('sessions');
  const [filter, setFilter] = useState<Filter>('all');
  const [sessions, error] = usePoll<Session[]>('/v1/sessions', 5000);

  const shown = (sessions ?? []).filter(s => ({
    all: true, ssh: s.protocol === 'ssh', web: s.protocol === 'ssh-web', sftp: s.files.length > 0, live: !s.ended_at, emergency: s.emergency,
  })[filter]);
  const sel = sessions?.find(s => s.id === selected) ?? shown.find(s => s.recording_sha256);

  const exportJson = async () => {
    const rows = await api<AuditEvent[]>('/v1/audit?limit=1000');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([rows.map(r => JSON.stringify(r)).join('\n') + '\n'], { type: 'application/x-ndjson' }));
    a.download = `orbital-audit-${new Date().toISOString().slice(0, 10)}.jsonl`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <>
      <div className="head rise">
        <div><h1>Audit &amp; replay</h1><p className="sub">Every session, file transfer and recording, with the reason it was made.</p></div>
        <div className="flex-1" />
        <Seg label="View" value={tab} onChange={setTab} options={[['sessions', 'Sessions'], ['events', 'Events']]} />
        <button className="btn" onClick={exportJson}>Export JSON</button>
      </div>
      {error && <p className="small" style={{ color: 'var(--bad)' }}>{error}</p>}
      {tab === 'events' ? <Events /> : (
        <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
          <div className="card rise" style={{ '--i': 1 } as React.CSSProperties}>
            <div className="row pad" style={{ paddingBottom: 0 }}>
              <Seg label="Filter sessions" value={filter} onChange={setFilter}
                options={[['all', 'All'], ['ssh', 'SSH'], ['web', 'Browser'], ['sftp', 'SFTP'], ['live', 'Live'], ['emergency', 'Break-glass']]} />
            </div>
            <div className="tablewrap mt-2">
              <table className="t">
                <thead><tr><th>When</th><th>User</th><th>Target</th><th>Reason</th><th /></tr></thead>
                <tbody>
                  {shown.map(s => (
                    <tr key={s.id} className={`click ${sel?.id === s.id ? 'sel' : ''}`} onClick={() => { location.hash = `audit/${s.id}`; }}>
                      <td className="small">{clock(s.started_at)}</td>
                      <td><b>{s.username}</b></td>
                      <td className="whitespace-nowrap">
                        <span className={`chip ${s.emergency ? 'bad' : 'acc'}`}>{s.files.length ? 'sftp' : s.protocol === 'ssh-web' ? 'browser' : 'ssh'}</span> {s.login}@{s.node_name}
                      </td>
                      <td className="small">{s.reason ?? ''}</td>
                      <td onClick={e => e.stopPropagation()}>
                        {!s.ended_at ? (
                          <span className="row" style={{ flexWrap: 'nowrap' }}><span className="dot live" />
                            {can(me, 'recordings:view') ? <a className="btn sm" href={`#live/${s.id}`}>Watch</a> : <span className="small">live</span>}
                          </span>
                        ) : s.files.length ? <span className="small">{s.files.length} file{s.files.length > 1 ? 's' : ''}</span>
                          : s.recording_sha256 && can(me, 'recordings:view') ? <a className="btn sm" href={`#audit/${s.id}`}>Replay</a>
                          : <span className="small">{s.end_reason}</span>}
                      </td>
                    </tr>
                  ))}
                  {sessions && !shown.length && <tr><td colSpan={5} className="small text-center">No sessions.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
          {sel && <Detail s={sel} />}
        </div>
      )}
    </>
  );
}

function Detail({ s }: { s: Session }) {
  const me = useMe();
  const [events] = usePoll<AuditEvent[]>(`/v1/audit?session=${s.id}&limit=100`, 0);
  const t0 = new Date(s.started_at).getTime();
  const rel = (at: string) => { const d = Math.max(0, Math.round((new Date(at).getTime() - t0) / 1000)); return `${Math.floor(d / 60)}:${String(d % 60).padStart(2, '0')}`; };
  const rows: [string, React.ReactNode][] = [
    [s.started_at, <>Session started · reason "{s.reason}"{s.emergency && <> · <span className="chip bad">break-glass</span></>}</>],
    ...s.files.map(f => [f.at, <><span className="chip">sftp</span> {f.op} <span className="mono">{f.path}</span>{f.bytes ? ` ${(f.bytes / 1024).toFixed(1)} KB` : ''}</>] as [string, React.ReactNode]),
    ...(events ?? []).filter(e => e.kind === 'session.viewed_live' || e.kind === 'session.killed')
      .map(e => [e.at, e.kind === 'session.killed' ? <>Killed: {String(e.data.reason)}</> : <>Viewed live by <b>{e.actor}</b></>] as [string, React.ReactNode]),
    ...(s.ended_at ? [[s.ended_at, <>Ended · {s.end_reason}</>] as [string, React.ReactNode]] : []),
  ];
  rows.sort((a, b) => a[0].localeCompare(b[0]));
  return (
    <div className="rise" style={{ '--i': 2 } as React.CSSProperties}>
      {s.recording_sha256 && can(me, 'recordings:view') && <Replay session={s} />}
      <div className="card pad mt-3">
        <label className="f">Session events</label>
        {rows.map(([at, body], i) => <div className="ev" key={i}><time>{rel(at)}</time><div>{body}</div></div>)}
      </div>
    </div>
  );
}

function Events() {
  const [events] = usePoll<AuditEvent[]>('/v1/audit?limit=200', 10000);
  const sev = (s: string) => (s === 'high' ? 'bad' : s === 'warn' ? 'warn' : '');
  return (
    <div className="card rise">
      <div className="tablewrap">
        <table className="t">
          <thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Details</th></tr></thead>
          <tbody>
            {events?.map(e => (
              <tr key={e.id}>
                <td className="small whitespace-nowrap">{new Date(e.at).toLocaleString()}</td>
                <td><span className={`chip ${sev(e.severity)}`}>{e.kind}</span></td>
                <td>{e.actor ?? <span className="small">system</span>}</td>
                <td className="small mono break-all">{JSON.stringify(e.data)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
