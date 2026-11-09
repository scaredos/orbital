import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import { api, can, MeProvider, SearchCtx, setCsrf, usePoll, type Approval, type Me } from './api';
import { Backdrop, Icon, initials, Logo } from './ui';
import { Nodes } from './views/Nodes';
import { AddNode } from './views/AddNode';
import { Request } from './views/Request';
import { Approvals } from './views/Approvals';
import { Audit } from './views/Audit';
import { Policy } from './views/Policy';
import { Roles } from './views/Roles';
import { Live, Terminal } from './views/Terminal';


function useRoute() {
  const get = () => (location.hash.slice(1) || 'nodes').split('/');
  const [r, setR] = useState(get);
  useEffect(() => {
    const f = () => { setR(get()); window.scrollTo(0, 0); };
    addEventListener('hashchange', f);
    return () => removeEventListener('hashchange', f);
  }, []);
  return r;
}

function toggleTheme() {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
  try { localStorage.setItem('orbital-theme', root.dataset.theme); } catch { /* storage unavailable */ }
}
try { const t = localStorage.getItem('orbital-theme'); if (t) document.documentElement.dataset.theme = t; } catch { /* ignore */ }

function Shell({ me }: { me: Me }) {
  const [view, arg] = useRoute();
  const [search, setSearch] = useState('');
  const [approvals] = usePoll<Approval[]>(can(me, 'approvals:decide') ? '/v1/approvals' : null, 10000);
  const pending = approvals?.filter(a => a.status === 'pending').length ?? 0;
  const nav: [string, string, string, boolean][] = [
    ['nodes', 'nodes', 'Nodes', true],
    ['add-node', 'plus', 'Add node', can(me, 'nodes:write')],
    ['request', 'request', 'Request access', true],
    ['approvals', 'approvals', 'Approvals', can(me, 'approvals:decide')],
    ['audit', 'audit', 'Audit & replay', can(me, 'audit:read')],
    ['policy', 'policy', 'Policy', can(me, 'policy:read')],
    ['roles', 'roles', 'Roles', can(me, 'rbac:write')],
    ['terminal', 'terminal', 'Terminal', true],
  ];
  const current = view === 'live' ? 'audit' : view;
  const screens: Record<string, React.ReactNode> = {
    nodes: <Nodes />,
    'add-node': <AddNode />,
    request: <Request node={arg} />,
    approvals: <Approvals />,
    audit: <Audit session={arg} />,
    policy: <Policy />,
    roles: <Roles />,
    terminal: <Terminal grant={arg} />,
    live: <Live session={arg} />,
  };
  const logout = () => api('/v1/auth/logout', 'POST').finally(() => location.reload());
  return (
    <MeProvider value={me}>
      <SearchCtx.Provider value={search}>
        <a href="#main-content" className="skip-link" onClick={e => { e.preventDefault(); document.getElementById('main-content')?.focus(); }}>Skip to main content</a>
        <Backdrop />
        <div className="app">
          <aside className="side">
            <div className="brand"><Logo /><span>Orbital</span></div>
            <nav className="nav" aria-label="Primary">
              {nav.filter(n => n[3]).map(([id, icon, label]) => (
                <a key={id} href={`#${id}`} aria-current={current === id ? 'page' : undefined}>
                  <Icon name={icon} /><span className="lbl">{label}</span>
                  {id === 'approvals' && pending > 0 && <span className="count" aria-label={`${pending} pending`}>{pending}</span>}
                </a>
              ))}
            </nav>
            <div className="foot">orbital · replica {me.replica}</div>
          </aside>
          <div className="min-w-0">
            <header className="top">
              <label className="search">
                <Icon name="search" size={16} />
                <input placeholder="Search nodes, labels, services…" aria-label="Search nodes" value={search}
                  onChange={e => { setSearch(e.target.value); if (view !== 'nodes') location.hash = 'nodes'; }} />
              </label>
              <div className="flex-1" />
              <button className="iconbtn" onClick={toggleTheme} aria-label="Toggle dark or light theme" title="Toggle theme"><Icon name="moon" /></button>
              <div className="avatar" title={`${me.username} · ${me.groups.join(', ') || 'no groups'}`}>{initials(me.username)}</div>
              <button className="iconbtn" onClick={logout} aria-label="Sign out" title="Sign out"><Icon name="logout" /></button>
            </header>
            <main className="content" id="main-content" tabIndex={-1}>
              <section className="view" key={view + (arg ?? '')}>{screens[view] ?? <Nodes />}</section>
            </main>
          </div>
        </div>
      </SearchCtx.Provider>
    </MeProvider>
  );
}

function SignIn({ sso }: { sso: boolean }) {
  const [pw, setPw] = useState('');
  const [error, setError] = useState('');
  const breakglass = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api('/v1/auth/password', 'POST', { password: pw }); location.reload(); } catch (x) { setError((x as Error).message); }
  };
  return (
    <>
      <Backdrop />
      <main className="relative z-[2] min-h-screen grid place-items-center p-4">
        <div className="card pad w-full max-w-sm view">
          <div className="brand" style={{ padding: '4px 0 14px' }}><Logo /><span>Orbital</span></div>
          <h1>Sign in</h1>
          <p className="sub">Zero-trust access to your infrastructure. Every session needs a reason and is recorded.</p>
          {sso && <a className="btn primary w-full justify-center" href="/v1/auth/login">Sign in with SSO</a>}
          <details className="mt-4" open={!sso}>
            <summary className="small cursor-pointer">Break-glass admin</summary>
            <form className="mt-3" onSubmit={breakglass}>
              <label className="f" htmlFor="pw">Local admin password</label>
              <input id="pw" className="input" type="password" autoComplete="current-password" value={pw} onChange={e => setPw(e.target.value)} />
              <p className="hint">Use only when SSO is down. Every use pages security.</p>
              {error && <p className="hint" style={{ color: 'var(--bad)' }}>{error}</p>}
              <button className="btn danger mt-2" disabled={!pw}>Sign in as admin</button>
            </form>
          </details>
        </div>
      </main>
    </>
  );
}

function Root() {
  const [state, setState] = useState<Me | 'login' | 'loading'>('loading');
  useEffect(() => {
    api<Me>('/v1/me').then(me => { setCsrf(me.csrf); setState(me); }, () => setState('login'));
  }, []);
  if (state === 'loading') return null;
  // ponytail: SSO button always shown; /v1/auth/login answers 404 when no IdP is configured
  if (state === 'login') return <SignIn sso />;
  return <Shell me={state} />;
}

createRoot(document.getElementById('root')!).render(<StrictMode><Root /></StrictMode>);
