import { useState } from 'react';
import { api, stepUp, useMe, usePoll } from '../api';
import { Callout } from '../ui';

type Role = { name: string; permissions: string[]; builtin: boolean };
type Binding = { group: string; role: string; team: string | null };
type Rbac = { catalog: string[]; roles: Role[]; bindings: Binding[] };

export function Roles() {
  const me = useMe();
  const [data, error, reload] = usePoll<Rbac>('/v1/rbac', 0);
  const [edit, setEdit] = useState<Role & { isNew?: boolean }>();
  const [bind, setBind] = useState({ group: '', role: 'read-only', team: '' });
  const [msg, setMsg] = useState('');

  const run = async (f: () => Promise<unknown>) => {
    if (!me.fresh) return stepUp();
    setMsg('');
    try { await f(); reload(); } catch (e) { setMsg((e as Error).message); }
  };
  const saveRole = () => edit && run(async () => { await api(`/v1/rbac/roles/${encodeURIComponent(edit.name)}`, 'PUT', { permissions: edit.permissions }); setEdit(undefined); });

  return (
    <>
      <div className="head rise">
        <div><h1>Roles</h1><p className="sub">Roles bundle permissions; bindings give them to OIDC groups, optionally only for nodes labelled <code>team=…</code>.</p></div>
        <div className="flex-1" />
        <button className="btn" onClick={() => setEdit({ name: "", permissions: [], builtin: false, isNew: true })}>New role</button>
      </div>
      {!me.fresh && <div className="mb-4"><Callout kind="acc">Changes ask you to re-authenticate with SSO.</Callout></div>}
      {(error || msg) && <div className="mb-4"><Callout kind="bad">{error || msg}</Callout></div>}
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="card rise" style={{ '--i': 1 } as React.CSSProperties}>
          <table className="t">
            <thead><tr><th>Role</th><th>Permissions</th><th /></tr></thead>
            <tbody>
              {data?.roles.map(r => (
                <tr key={r.name}>
                  <td className="name">{r.name}{r.builtin && <> <span className="chip">built-in</span></>}</td>
                  <td><div className="row">{r.permissions.map(p => <span key={p} className="chip mono">{p}</span>)}</div></td>
                  <td>{!r.builtin && <div className="row" style={{ flexWrap: 'nowrap' }}>
                    <button className="btn sm" onClick={() => setEdit(r)}>Edit</button>
                    <button className="btn sm danger" onClick={() => run(() => api(`/v1/rbac/roles/${encodeURIComponent(r.name)}`, 'DELETE'))}>Delete</button>
                  </div>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="grid gap-4 content-start">
          {edit && data && (
            <div className="card pad rise">
              <div className="field"><label className="f" htmlFor="rname">Role name</label>
                <input id="rname" className="input" value={edit.name} onChange={e => setEdit({ ...edit, name: e.target.value })} disabled={!edit.isNew} /></div>
              <fieldset className="field"><legend className="f">Permissions</legend>
                <div className="grid sm:grid-cols-2 gap-1">
                  {data.catalog.map(p => (
                    <label key={p} className="row mono small" style={{ flexWrap: 'nowrap' }}>
                      <input type="checkbox" checked={edit.permissions.includes(p)}
                        onChange={e => setEdit({ ...edit, permissions: e.target.checked ? [...edit.permissions, p] : edit.permissions.filter(x => x !== p) })} />{p}
                    </label>
                  ))}
                </div>
                <div className="hint">policy:write, devices:write and rbac:write only apply through bindings without a team.</div>
              </fieldset>
              <div className="row"><button className="btn primary" disabled={!edit.name} onClick={saveRole}>Save role</button><button className="btn" onClick={() => setEdit(undefined)}>Cancel</button></div>
            </div>
          )}
          <div className="card rise" style={{ '--i': 2 } as React.CSSProperties}>
            <table className="t">
              <thead><tr><th>OIDC group</th><th>Role</th><th>Scope</th><th /></tr></thead>
              <tbody>
                {data?.bindings.map(b => (
                  <tr key={`${b.group}/${b.role}/${b.team}`}>
                    <td className="mono">{b.group}</td><td>{b.role}</td>
                    <td>{b.team ? <span className="chip">team=<b>{b.team}</b></span> : <span className="small">all nodes</span>}</td>
                    <td><button className="btn sm danger" onClick={() => run(() => api('/v1/rbac/bindings', 'DELETE', b))}>Remove</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <form className="row pad" style={{ borderTop: '1px solid var(--line)' }}
              onSubmit={e => { e.preventDefault(); run(async () => { await api('/v1/rbac/bindings', 'POST', { ...bind, team: bind.team || null }); setBind({ ...bind, group: '', team: '' }); }); }}>
              <input className="input" style={{ width: 160 }} aria-label="OIDC group" placeholder="OIDC group" value={bind.group} onChange={e => setBind({ ...bind, group: e.target.value })} />
              <select className="input" style={{ width: 150 }} aria-label="Role" value={bind.role} onChange={e => setBind({ ...bind, role: e.target.value })}>
                {data?.roles.map(r => <option key={r.name}>{r.name}</option>)}
              </select>
              <input className="input" style={{ width: 130 }} aria-label="Team (optional)" placeholder="team (optional)" value={bind.team} onChange={e => setBind({ ...bind, team: e.target.value })} />
              <button className="btn primary" disabled={!bind.group}>Bind</button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}
