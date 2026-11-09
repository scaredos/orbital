import { useEffect, useRef, useState } from 'react';
import { api, type Node } from '../api';
import { Callout, CopyButton, Seg } from '../ui';

type Join = { token: string; url: string; expires_in: number; command: string };

export function parseLabels(s: string): Record<string, string> {
  return Object.fromEntries(s.split(',').map(p => p.trim()).filter(Boolean).map(p => {
    const [k, ...v] = p.split('=');
    return [k.trim(), v.join('=').trim()];
  }));
}

export function AddNode() {
  const [arch, setArch] = useState<'x86_64' | 'aarch64'>('x86_64');
  const [labels, setLabels] = useState('');
  const [join, setJoin] = useState<Join & { at: number }>();
  const [error, setError] = useState('');
  const [enrolled, setEnrolled] = useState<Node>();
  const known = useRef<Set<string>>(new Set());

  const generate = async () => {
    setError(''); setEnrolled(undefined);
    try {
      known.current = new Set((await api<Node[]>('/v1/nodes')).map(n => n.name));
      setJoin({ ...(await api<Join>('/v1/nodes/join', 'POST', { labels: parseLabels(labels) })), at: Date.now() });
    } catch (e) { setError((e as Error).message); }
  };

  // live: watch for the node that enrolls with this token
  useEffect(() => {
    if (!join || enrolled) return;
    const t = setInterval(async () => {
      const fresh = (await api<Node[]>('/v1/nodes').catch(() => [])).find(n => !known.current.has(n.name));
      if (fresh) setEnrolled(fresh);
    }, 3000);
    return () => clearInterval(t);
  }, [join, enrolled]);

  const step = enrolled ? 3 : join ? 2 : 1;
  const cls = (n: number) => `step ${step > n ? 'done' : step === n ? 'on' : ''}`;
  const dl = join ? `${join.url}?arch=${arch}` : '';
  const cmd = join ? `curl -fsSL '${dl}' \\\n  -o orbital-agent && chmod +x orbital-agent\nsudo ./orbital-agent install` : '';
  const labelFlags = Object.entries(parseLabels(labels)).map(([k, v]) => ` \\\n  --label ${k}=${v}`).join('');

  return (
    <>
      <div className="rise"><h1>Add a node</h1><p className="sub">Download a pre-configured agent. It carries a single-use join token and this orchestrator's CA fingerprint.</p></div>
      <div className="steps rise" style={{ '--i': 1 } as React.CSSProperties}>
        <div className={cls(1)}><i>{step > 1 ? '✓' : 1}</i>Configure</div>
        <div className={cls(2)}><i>{step > 2 ? '✓' : 2}</i>Install</div>
        <div className={cls(3)}><i>3</i>Online</div>
      </div>
      <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
        <div className="card pad rise" style={{ '--i': 2 } as React.CSSProperties}>
          <div className="field"><label className="f">Architecture</label>
            <Seg label="Architecture" value={arch} onChange={setArch} options={[['x86_64', 'x86_64'], ['aarch64', 'aarch64']]} /></div>
          <div className="field">
            <label className="f" htmlFor="pre">Pre-set labels <span className="small">(optional)</span></label>
            <input id="pre" className="input" placeholder="env=prod, team=data" value={labels} onChange={e => setLabels(e.target.value)} disabled={!!join && !enrolled} />
            <div className="hint">Pinned on the node at enrollment; the installer can't override them. Team admins must include their team.</div>
          </div>
          {!join || enrolled ? (
            <button className="btn primary" onClick={generate}>{enrolled ? 'Add another node' : 'Generate install command'}</button>
          ) : (
            <>
              <label className="f">Run on the host</label>
              <div className="codebox mono"><CopyButton text={cmd} />{cmd}</div>
              <p className="hint">Or download <a href={dl}>orbital-agent-{arch}</a> directly. The token is single use and expires at {new Date(join.at + join.expires_in * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.</p>
              <details className="mt-2"><summary className="small cursor-pointer">Non-interactive (Ansible / cloud-init)</summary>
                <div className="codebox mono mt-2">sudo ./orbital-agent install -y --name {'<name>'}{labelFlags} \{'\n'}  --expose ssh=22</div>
              </details>
            </>
          )}
          {error && <div className="mt-3"><Callout kind="bad">{error}</Callout></div>}
        </div>
        <div className="card pad rise" style={{ '--i': 3 } as React.CSSProperties}>
          <label className="f">What the installer asks</label>
          <div className="codebox mono" style={{ fontSize: 12, lineHeight: 1.7 }}>
            ? Node name <span style={{ color: '#6b739a' }}>(hostname)</span>{'\n'}
            ? Labels <span style={{ color: '#6b739a' }}>{labels || 'env=prod, team=data'}</span>{'\n'}
            ? Expose services  <span style={{ color: '#6b739a' }}>found listening:</span>{'\n'}
            {'  '}<span style={{ color: '#34d399' }}>◉</span> 22    sshd       → ssh{'\n'}
            {'  '}◯ 9100  node_exp{'\n'}
            ? Trust Orbital SSH CA in sshd? <span style={{ color: '#34d399' }}>Yes</span>{'\n'}
            ? Install systemd service? <span style={{ color: '#34d399' }}>Yes</span>{'\n'}
            <span style={{ color: '#34d399' }}>✓</span> enrolled · cert valid 30d · tunnel up
          </div>
          {join && (
            <div className={`wait mt-4 ${enrolled ? 'ok' : ''}`} role="status" aria-live="polite">
              <div className="radar" aria-hidden="true" />
              <div>
                <div className="name">{enrolled ? `${enrolled.name} enrolled` : 'Waiting for the node to enroll…'}</div>
                <div className="small">{enrolled ? `Exposing ${Object.keys(enrolled.services).join(', ') || 'no services'} · ${enrolled.online ? 'tunnel up' : 'connecting'}` : 'This updates live when the agent connects.'}</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
