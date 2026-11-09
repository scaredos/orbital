import { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { api, can, useMe, usePoll, wsUrl, type Grant, type Session } from '../api';
import { usable } from './Request';
import { Callout, Empty, Icon } from '../ui';

const theme = { background: '#00000000', foreground: '#d6dcff', cursor: '#d6dcff', selectionBackground: '#8b8bff55' };

/** An xterm in `ref`, fitted to its box; `cols/rows` pins the size (replay). */
export function useXterm(opts: { readOnly?: boolean; cols?: number; rows?: number } = {}) {
  const ref = useRef<HTMLDivElement>(null);
  const [term, setTerm] = useState<XTerm>();
  useEffect(() => {
    const t = new XTerm({
      theme, fontFamily: '"JetBrains Mono", ui-monospace, Menlo, monospace', fontSize: 13, cursorBlink: !opts.readOnly,
      disableStdin: opts.readOnly, allowTransparency: true, scrollback: 5000, cols: opts.cols ?? 80, rows: opts.rows ?? 24,
    });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(ref.current!);
    const refit = () => { if (!opts.cols) try { fit.fit(); } catch { /* hidden */ } };
    refit();
    addEventListener('resize', refit);
    setTerm(t);
    return () => { removeEventListener('resize', refit); t.dispose(); };
  }, [opts.readOnly, opts.cols, opts.rows]);
  return [ref, term] as const;
}

type Ctl = { session?: string; viewers?: string[]; closed?: string };

// ---------------------------------------------------------------- browser SSH

export function Terminal({ grant: id }: { grant?: string }) {
  if (!id) return <PickGrant />;
  return <Shell id={id} />;
}

function PickGrant() {
  const [grants] = usePoll<Grant[]>('/v1/grants', 0);
  const open = (grants ?? []).filter(g => usable(g) && g.service === 'ssh');
  return (
    <>
      <div className="head rise"><div><h1>Terminal</h1><p className="sub">Browser SSH through the same recorded relay as <code>orbital ssh</code>.</p></div>
        <div className="flex-1" /><a className="btn primary" href="#request">Request access</a></div>
      <div className="grid gap-3">
        {open.map(g => (
          <a key={g.id} className="card pad row no-underline" style={{ color: 'var(--text)' }} href={`#terminal/${g.id}`}>
            <Icon name="terminal" size={18} /><b>{g.login}@{g.node_name}</b><span className="small">"{g.reason}"</span>
            <span className="flex-1" /><span className="chip ok">until {new Date(g.expires_at!).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </a>
        ))}
        {grants && !open.length && <Empty>No active SSH grants. Request access to a node first.</Empty>}
      </div>
    </>
  );
}

function Shell({ id }: { id: string }) {
  const [ref, term] = useXterm();
  const [grant, setGrant] = useState<Grant>();
  const [ctl, setCtl] = useState<Ctl>({});
  const [attempt, setAttempt] = useState(0);
  const ws = useRef<WebSocket>(null);

  useEffect(() => { api<Grant>(`/v1/grants/${id}`).then(setGrant, e => setCtl({ closed: e.message })); }, [id]);

  useEffect(() => {
    if (!term) return;
    term.reset();
    setCtl({});
    const sock = new WebSocket(wsUrl(`/v1/terminal?grant=${id}&cols=${term.cols}&rows=${term.rows}`));
    sock.binaryType = 'arraybuffer';
    ws.current = sock;
    const enc = new TextEncoder();
    const subs = [
      term.onData(d => sock.readyState === 1 && sock.send(enc.encode(d))),
      term.onResize(({ cols, rows }) => sock.readyState === 1 && sock.send(JSON.stringify({ resize: [cols, rows] }))),
    ];
    sock.onmessage = e => {
      if (typeof e.data === 'string') setCtl(c => ({ ...c, ...JSON.parse(e.data) }));
      else term.write(new Uint8Array(e.data));
    };
    sock.onclose = () => setCtl(c => ({ ...c, closed: c.closed ?? 'connection closed' }));
    term.focus();
    return () => { subs.forEach(s => s.dispose()); sock.close(); };
  }, [term, id, attempt]);

  const left = grant?.expires_at ? Math.max(0, Math.round((new Date(grant.expires_at).getTime() - Date.now()) / 60000)) : 0;
  return (
    <>
      <div className="head rise">
        <div><h1>{grant?.node_name ?? 'Terminal'}</h1>
          <p className="sub">Browser SSH as <b>{grant?.login}</b>{grant?.expires_at && <> · grant expires in {left} min</>}</p></div>
        <div className="flex-1" />
        <div className="row">
          <span className="chip acc">recorded</span><span className="chip">SSH CA cert · 5 min</span>
          {ctl.closed
            ? <button className="btn sm" onClick={() => setAttempt(a => a + 1)}>Reconnect</button>
            : <button className="btn sm danger" onClick={() => ws.current?.close()}>Disconnect</button>}
        </div>
      </div>
      <div className="term rise" style={{ '--i': 1 } as React.CSSProperties}>
        <div className="bar"><span className={`dot ${ctl.closed ? 'bad' : 'ok'}`} /><b>{grant ? `${grant.login}@${grant.node_name}` : '…'}</b>
          {grant?.emergency && <span className="chip bad">break-glass</span>}
          <span className="flex-1" />{grant && <span>Reason: "{grant.reason}"</span>}</div>
        {!!ctl.viewers?.length && <div className="banner" role="status"><Icon name="eye" size={14} />{ctl.viewers.join(', ')} {ctl.viewers.length > 1 ? 'are' : 'is'} watching this session</div>}
        {ctl.closed && <div className="banner bad" role="status">Session ended: {ctl.closed}</div>}
        <div className="screen" ref={ref} aria-label="Terminal" />
      </div>
    </>
  );
}

// ---------------------------------------------------------------- live view

export function Live({ session: sid }: { session?: string }) {
  const me = useMe();
  const [ref, term] = useXterm({ readOnly: true });
  const [sessions] = usePoll<Session[]>(can(me, 'audit:read') ? '/v1/sessions' : null, 0);
  const [closed, setClosed] = useState('');
  const [killed, setKilled] = useState('');
  const s = sessions?.find(x => x.id === sid);

  useEffect(() => {
    if (!term || !sid) return;
    const sock = new WebSocket(wsUrl(`/v1/sessions/${sid}/live`));
    sock.binaryType = 'arraybuffer';
    sock.onmessage = e => {
      if (typeof e.data === 'string') setClosed(JSON.parse(e.data).closed ?? '');
      else term.write(new Uint8Array(e.data));
    };
    sock.onclose = ev => setClosed(c => c || (ev.code === 1006 ? 'could not attach (session ended, on another replica, or no permission)' : 'closed'));
    return () => sock.close();
  }, [term, sid]);

  const kill = async () => {
    if (!confirm('Kill this session? The user is disconnected immediately.')) return;
    try { await api(`/v1/sessions/${sid}/kill`, 'POST'); setKilled('Kill requested'); } catch (e) { setKilled((e as Error).message); }
  };
  return (
    <>
      <div className="head rise">
        <div><h1>Live: {s ? `${s.login}@${s.node_name}` : 'session'}</h1>
          <p className="sub">Read-only view{s && <> of <b>{s.username}</b>'s session</>}. They see a banner saying you are watching.</p></div>
        <div className="flex-1" />
        <div className="row">
          <span className="chip bad"><span className="dot live" /> live</span>
          {can(me, 'sessions:kill') && !closed && <button className="btn sm danger" onClick={kill}>Kill session</button>}
        </div>
      </div>
      {killed && <div className="mb-3"><Callout kind="warn">{killed}</Callout></div>}
      <div className="term rise">
        <div className="bar"><span className={`dot ${closed ? 'bad' : 'live'}`} /><b>{s ? `${s.username} → ${s.login}@${s.node_name}` : sid}</b>
          <span className="flex-1" />{s?.reason && <span>Reason: "{s.reason}"</span>}</div>
        <div className="banner" role="status"><Icon name="eye" size={14} />Watching read-only · your keystrokes are not sent</div>
        {closed && <div className="banner bad" role="status">{closed}</div>}
        <div className="screen" ref={ref} aria-label="Live session output" />
      </div>
    </>
  );
}

// ---------------------------------------------------------------- recording replay (asciicast v2)

type Cast = { width: number; height: number; events: [number, string, string][]; total: number };

/** Parses asciicast v2, squeezing idle gaps to 2s like asciinema's idle_time_limit. */
export function parseCast(text: string): Cast {
  const [head, ...lines] = text.split('\n').filter(Boolean);
  const h = JSON.parse(head);
  let t = 0, prev = 0;
  const events = lines.map(l => {
    const [at, kind, data] = JSON.parse(l) as [number, string, string];
    t += Math.min(at - prev, 2);
    prev = at;
    return [t, kind, data] as [number, string, string];
  });
  return { width: h.width || 80, height: h.height || 24, events, total: t };
}

export function Replay({ session }: { session: Session }) {
  const [cast, setCast] = useState<Cast>();
  const [error, setError] = useState('');
  useEffect(() => {
    setCast(undefined); setError('');
    fetch(`/v1/sessions/${session.id}/recording`, { credentials: 'same-origin' })
      .then(async r => r.ok ? setCast(parseCast(await r.text())) : setError((await r.json().catch(() => ({}))).error ?? `HTTP ${r.status}`))
      .catch(e => setError(String(e)));
  }, [session.id]);
  const started = new Date(session.started_at);
  const secs = session.ended_at ? Math.round((new Date(session.ended_at).getTime() - started.getTime()) / 1000) : 0;
  return (
    <div className="term">
      <div className="bar"><span className="dot ok" /><b>{session.login}@{session.node_name}</b>
        <span>{started.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · {Math.floor(secs / 60)}m {secs % 60}s</span>
        <span className="flex-1" />{session.recording_sha256 && <span className="mono" title={session.recording_sha256}>sha256 {session.recording_sha256.slice(0, 4)}…{session.recording_sha256.slice(-2)}</span>}</div>
      {error ? <div className="banner bad">{error}</div> : cast ? <Player cast={cast} /> : <div className="screen short" />}
    </div>
  );
}

function Player({ cast }: { cast: Cast }) {
  const [ref, term] = useXterm({ readOnly: true, cols: cast.width, rows: cast.height });
  const [pos, setPos] = useState(0);
  const [playing, setPlaying] = useState(!matchMedia('(prefers-reduced-motion: reduce)').matches);
  const shown = useRef(0); // events already written

  useEffect(() => { if (!playing && pos === 0) setPos(cast.total); }, []); // reduced motion: jump to the end
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => setPos(p => { if (p >= cast.total) { setPlaying(false); return p; } return Math.min(cast.total, p + 0.05); }), 50);
    return () => clearInterval(t);
  }, [playing, cast.total]);
  useEffect(() => {
    if (!term) return;
    let i = shown.current;
    if (cast.events[i - 1]?.[0] > pos) { term.reset(); i = 0; } // seeked backwards
    for (; i < cast.events.length && cast.events[i][0] <= pos; i++) {
      const [, kind, data] = cast.events[i];
      if (kind === 'o') term.write(data);
      else if (kind === 'r') { const [c, r] = data.split('x').map(Number); if (c && r) term.resize(c, r); }
    }
    shown.current = i;
  }, [pos, term, cast]);

  const tc = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  return (
    <>
      <div className="screen short overflow-auto" ref={ref} aria-label="Session replay output" />
      <div className="scrub">
        <button onClick={() => { if (pos >= cast.total) setPos(0); setPlaying(p => !p); }} aria-label="Play or pause replay">{playing ? '❚❚' : '▶'}</button>
        <input type="range" min={0} max={cast.total || 1} step={0.05} value={pos} aria-label="Replay position"
          onChange={e => { setPlaying(false); setPos(+e.target.value); }} />
        <span className="mono" style={{ fontSize: 12, color: '#9aa2c7' }}>{tc(pos)} / {tc(cast.total)}</span>
      </div>
    </>
  );
}
