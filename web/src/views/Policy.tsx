import { useEffect, useState } from 'react';
import { api, can, dur, stepUp, useMe, usePoll, type Node, type Rule } from '../api';
import { Callout, Tags, Toggle } from '../ui';
import { parseLabels } from './AddNode';

const blank = (n: number): Rule => ({
  name: `rule-${n}`, groups: [], node_labels: {}, services: ['ssh'], logins: ['{{user.username}}'],
  require_approval: false, emergency: false, max_ttl_secs: 3600,
});
const TTLS = [900, 1800, 3600, 7200, 14400, 28800];

/** Same label match as the orchestrator: every label must match, "*" = present. */
const matches = (r: Rule, n: Node) => Object.entries(r.node_labels).every(([k, v]) => k in n.labels && (v === '*' || n.labels[k] === v));

export function Policy() {
  const me = useMe();
  const editable = can(me, 'policy:write');
  const [saved, error] = usePoll<Rule[]>('/v1/policy', 0);
  const [nodes] = usePoll<Node[]>('/v1/nodes', 0);
  const [rules, setRules] = useState<Rule[]>([]);
  const [sel, setSel] = useState(0);
  const [msg, setMsg] = useState<['ok' | 'bad', string]>();
  useEffect(() => { if (saved) setRules(saved); }, [saved]);

  const r = rules[sel];
  const dirty = JSON.stringify(rules) !== JSON.stringify(saved ?? []);
  const set = (p: Partial<Rule>) => setRules(rs => rs.map((x, i) => (i === sel ? { ...x, ...p } : x)));
  const save = async () => {
    if (!me.fresh) return stepUp();
    try { await api('/v1/policy', 'PUT', rules); setMsg(['ok', `Saved ${rules.length} rules. Live sessions were re-checked.`]); }
    catch (e) { setMsg(['bad', (e as Error).message]); }
  };

  return (
    <>
      <div className="head rise">
        <div><h1>Policy</h1><p className="sub">Label-based rules. Anything not explicitly allowed is denied.</p></div>
        <div className="flex-1" />
        {editable && <button className="btn" onClick={() => { setRules(rs => [...rs, blank(rs.length + 1)]); setSel(rules.length); }}>New rule</button>}
        {editable && <button className="btn primary" disabled={!dirty} onClick={save}>{me.fresh ? 'Save policy' : 'Re-authenticate & save'}</button>}
      </div>
      {error && <Callout kind="bad">{error}</Callout>}
      {msg && <div className="mb-4"><Callout kind={msg[0]}>{msg[1]}</Callout></div>}
      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <div className="flex flex-col gap-2 rise" style={{ '--i': 1 } as React.CSSProperties} role="listbox" aria-label="Rules">
          {rules.map((x, i) => (
            <button key={i} className="rule" role="option" aria-selected={i === sel} onClick={() => setSel(i)}>
              <div className="tt">{x.name}{x.require_approval && <span className="chip warn">approval</span>}{x.emergency && <span className="chip bad">emergency</span>}</div>
              <div className="small">{x.groups.join(', ') || 'nobody'} → {Object.entries(x.node_labels).map(([k, v]) => `${k}=${v}`).join(', ') || 'any node'} · {x.services.join(', ')}</div>
            </button>
          ))}
          {saved && !rules.length && <div className="small">No rules: everything is denied.</div>}
        </div>
        {r && (
          <div className="card pad rise" style={{ '--i': 2 } as React.CSSProperties}>
            <div className="grid gap-4 xl:grid-cols-2">
              <fieldset disabled={!editable}>
                <div className="field"><label className="f" htmlFor="rn">Rule name</label><input id="rn" className="input" value={r.name} onChange={e => set({ name: e.target.value })} /></div>
                <div className="field"><label className="f">Who (OIDC groups, * = anyone signed in)</label><Tags label="Add group" placeholder="add group…" values={r.groups} onChange={groups => set({ groups })} disabled={!editable} /></div>
                <div className="field"><label className="f">Nodes where</label>
                  <Tags label="Add label selector" placeholder="label=value…" disabled={!editable}
                    values={Object.entries(r.node_labels).map(([k, v]) => `${k}=${v}`)} onChange={v => set({ node_labels: parseLabels(v.join(',')) })} /></div>
                <div className="field"><label className="f">Services</label><Tags label="Add service" placeholder="service…" values={r.services} onChange={services => set({ services })} disabled={!editable} /></div>
                <div className="field"><label className="f">Allowed logins</label><Tags label="Add login" placeholder="login…" values={r.logins} onChange={logins => set({ logins })} disabled={!editable} />
                  <div className="hint">root is only allowed if you list it here. {'{{user.username}}'} is the signed-in user.</div></div>
                <div className="field"><label className="f" htmlFor="mx">Max grant</label>
                  <select id="mx" className="input" value={r.max_ttl_secs} onChange={e => set({ max_ttl_secs: +e.target.value })}>
                    {[...new Set([...TTLS, r.max_ttl_secs])].sort((a, b) => a - b).map(t => <option key={t} value={t}>{dur(t)}</option>)}
                  </select></div>
                <div className="row mb-3" style={{ justifyContent: 'space-between' }}><span className="name">Require approval</span><Toggle accent label="Require approval" checked={r.require_approval} onChange={v => set({ require_approval: v })} disabled={!editable} /></div>
                <div className="row mb-3" style={{ justifyContent: 'space-between' }}><span className="name">Allow break-glass</span><Toggle label="Allow break-glass" checked={r.emergency} onChange={v => set({ emergency: v })} disabled={!editable} /></div>
                {editable && <button type="button" className="btn sm danger" onClick={() => { setRules(rs => rs.filter((_, i) => i !== sel)); setSel(0); }}>Delete rule</button>}
              </fieldset>
              <div>
                <label className="f">As code</label>
                <pre className="yaml mono">{JSON.stringify(r, null, 2)}</pre>
                <div className="mt-3"><Callout kind="acc">Matches <b>{(nodes ?? []).filter(n => matches(r, n)).length} nodes</b>. Saving re-checks live sessions, and ones that no longer match are ended.</Callout></div>
                {editable && !me.fresh && <p className="hint">Saving asks you to re-authenticate with SSO.</p>}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
