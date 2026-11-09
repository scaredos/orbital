import { useEffect, useState } from 'react';
import { ago, api, stepUp, useMe, usePoll, type Grant, type Node } from '../api';
import { Callout, Toggle } from '../ui';

const DRAFT = 'orbital-request-draft';
type Draft = { node: string; service: string; login: string; reason: string; emergency: boolean };

export const usable = (g: Grant) => g.status === 'approved' && !!g.expires_at && new Date(g.expires_at) > new Date();

export function Request({ node: preset }: { node?: string }) {
  const me = useMe();
  const [nodes] = usePoll<Node[]>('/v1/nodes', 0);
  const [grants, , reloadGrants] = usePoll<Grant[]>('/v1/grants', 5000);
  // survives the step-up round trip to the IdP
  const [d, setD] = useState<Draft>(() => {
    try { const s = sessionStorage.getItem(DRAFT); if (s) { sessionStorage.removeItem(DRAFT); return JSON.parse(s); } } catch { /* ignore */ }
    return { node: preset ? decodeURIComponent(preset) : '', service: 'ssh', login: me.username, reason: '', emergency: false };
  });
  const [grant, setGrant] = useState<Grant>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const online = (nodes ?? []).filter(n => n.online);
  const target = online.find(n => n.name === d.node);
  useEffect(() => { if (!d.node && online[0]) setD(x => ({ ...x, node: online[0].name })); }, [online, d.node]);

  // pending grant: poll until someone decides
  useEffect(() => {
    if (grant?.status !== 'pending') return;
    const t = setInterval(() => api<Grant>(`/v1/grants/${grant.id}`).then(setGrant, () => {}), 2000);
    return () => clearInterval(t);
  }, [grant]);

  const set = (p: Partial<Draft>) => setD(x => ({ ...x, ...p }));
  const reasonLen = d.reason.trim().length;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (d.emergency && !me.fresh) {
      try { sessionStorage.setItem(DRAFT, JSON.stringify(d)); } catch { /* ignore */ }
      return stepUp();
    }
    setBusy(true); setError(''); setGrant(undefined);
    try {
      const g = await api<Grant>('/v1/grants', 'POST', { node: d.node, service: d.service, login: d.login, reason: d.reason.trim(), emergency: d.emergency });
      setGrant(g); reloadGrants();
      if (usable(g) && g.service === 'ssh') location.hash = `terminal/${g.id}`;
    } catch (x) { setError((x as Error).message); }
    setBusy(false);
  };

  return (
    <>
      <div className="rise"><h1>Request access</h1><p className="sub">Every session needs a reason. Some rules also need an approver.</p></div>
      <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
        <form className="card pad rise" style={{ '--i': 1 } as React.CSSProperties} onSubmit={submit}>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="field"><label className="f" htmlFor="r-node">Node</label>
              <select id="r-node" className="input" value={d.node} onChange={e => set({ node: e.target.value, service: 'ssh' })}>
                {!online.length && <option value="">No online nodes</option>}
                {online.map(n => <option key={n.name}>{n.name}</option>)}
              </select></div>
            <div className="field"><label className="f" htmlFor="r-svc">Service</label>
              <select id="r-svc" className="input" value={d.service} onChange={e => set({ service: e.target.value })}>
                {Object.entries(target?.services ?? { ssh: 22 }).map(([s, p]) => <option key={s} value={s}>{s} :{p}</option>)}
              </select>
              {d.service !== 'ssh' && <div className="hint">Browser access is SSH only for now; use <code>orbital proxy</code> for other services.</div>}
            </div>
            <div className="field"><label className="f" htmlFor="r-login">Login as</label>
              <input id="r-login" className="input mono" value={d.login} onChange={e => set({ login: e.target.value })} />
              <div className="hint">Must be listed in a rule's logins. root only if a rule names it.</div></div>
          </div>
          <div className="field"><label className="f" htmlFor="reason">Reason <span style={{ color: 'var(--bad)' }}>*</span></label>
            <textarea id="reason" className="input" required minLength={10} maxLength={1000} value={d.reason} onChange={e => set({ reason: e.target.value })}
              placeholder="e.g. INC-2291: replication lag on db-prod-01, need to inspect pg_stat_replication" />
            <div className="hint">{reasonLen}/10 characters minimum · stored in the audit log and shown to approvers</div></div>
          <div className="row field" style={{ justifyContent: 'space-between', padding: '12px 14px', border: '1px solid var(--line)', borderRadius: 10, flexWrap: 'nowrap' }}>
            <div><div className="name">Break-glass</div><div className="small">Self-approve now, if a rule allows emergency access. Sends a high-severity alert and flags the session for review.</div></div>
            <Toggle checked={d.emergency} onChange={v => set({ emergency: v })} label="Break-glass emergency access" />
          </div>
          {d.emergency && <div className="field"><Callout kind="bad"><b>Emergency access.</b> {me.fresh ? 'Security gets paged and the session is marked for review.' : "You'll be asked to re-authenticate with SSO first. Security gets paged and the session is marked for review."}</Callout></div>}
          {error && <div className="field"><Callout kind="bad">{error}</Callout></div>}
          {grant?.status === 'pending' && <div className="field" role="status"><Callout kind="warn">Waiting for an approver. Rule requires approval; this page updates when someone decides.</Callout></div>}
          {grant && usable(grant) && <div className="field"><Callout kind="ok">Approved until {new Date(grant.expires_at!).toLocaleTimeString()}. <a href={`#terminal/${grant.id}`}>Open terminal</a></Callout></div>}
          {grant && (grant.status === 'denied' || grant.status === 'revoked') && <div className="field"><Callout kind="bad">Request {grant.status}.</Callout></div>}
          <div className="row">
            <button className={`btn ${d.emergency ? 'danger solid' : 'primary'}`} disabled={busy || reasonLen < 10 || !d.node}>
              {d.emergency ? (me.fresh ? 'Break glass & connect' : 'Re-authenticate & break glass') : 'Request access'}
            </button>
            <span className="small">Recorded session · SSH CA cert valid 5 min</span>
          </div>
        </form>
        <div className="card pad rise" style={{ '--i': 2 } as React.CSSProperties}>
          <label className="f">Or from your terminal</label>
          <div className="codebox mono">$ ssh {d.login || me.username}@{d.node || 'node'}.orbital{'\n'}
            <span style={{ color: '#6b739a' }}>orbital: reason for access?</span> {d.reason.slice(0, 40) || 'INC-2291 replication lag'}{'\n'}
            <span style={{ color: '#34d399' }}>orbital: grant approved</span>
          </div>
          <p className="hint">Run <code>orbital setup</code> once and plain <code>ssh</code>, <code>scp</code>, <code>rsync</code> and VS Code Remote-SSH all go through Orbital.</p>
          <hr style={{ border: 0, borderTop: '1px solid var(--line)', margin: '16px 0' }} />
          <label className="f">My recent grants</label>
          <div>
            {(grants ?? []).slice(0, 8).map(g => (
              <div className="ev" key={g.id}>
                <time>{ago(g.created_at)}</time>
                <div>
                  <b>{g.node_name}</b> · {g.service} as {g.login}{' '}
                  <span className={`chip ${usable(g) ? 'ok' : g.status === 'pending' ? 'warn' : g.status === 'approved' ? '' : 'bad'}`}>{usable(g) ? 'active' : g.status === 'approved' ? 'expired' : g.status}</span>
                  {g.emergency && <> <span className="chip bad">break-glass</span></>}
                  <div className="small">"{g.reason}"</div>
                  {usable(g) && g.service === 'ssh' && <a className="small" href={`#terminal/${g.id}`}>Open terminal</a>}
                </div>
              </div>
            ))}
            {grants && !grants.length && <div className="small">No grants yet.</div>}
          </div>
        </div>
      </div>
    </>
  );
}
