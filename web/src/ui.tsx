import { useState, type ReactNode } from 'react';

const paths: Record<string, ReactNode> = {
  nodes: <><rect x="3" y="4" width="18" height="6" rx="2" /><rect x="3" y="14" width="18" height="6" rx="2" /><path d="M7 7h.01M7 17h.01" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  request: <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" />,
  approvals: <><path d="M9 12l2 2 4-4" /><circle cx="12" cy="12" r="9" /></>,
  audit: <><path d="M4 4h16v16H4z" /><path d="M8 9h8M8 13h8M8 17h5" /></>,
  policy: <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" />,
  roles: <><circle cx="9" cy="8" r="4" /><path d="M2 21c0-4 3-7 7-7s7 3 7 7M17 11l2 2 4-4" /></>,
  terminal: <path d="M4 17l6-5-6-5M12 19h8" />,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></>,
  warn: <><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 16v-4M12 8h.01" /></>,
  eye: <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></>,
  logout: <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />,
};

export function Icon({ name, size }: { name: keyof typeof paths | string; size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      {paths[name]}
    </svg>
  );
}

export function Logo() {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true">
      <circle cx="16" cy="16" r="6" fill="var(--accent)" />
      <ellipse cx="16" cy="16" rx="14" ry="6" fill="none" stroke="var(--accent-2)" strokeWidth="2" transform="rotate(-25 16 16)" />
    </svg>
  );
}

export function Backdrop() {
  return (
    <>
      <div className="layer wash" aria-hidden="true" />
      <div className="layer" aria-hidden="true"><div className="glow a" /><div className="glow b" /></div>
      <div className="layer" aria-hidden="true">
        <svg className="orbits" viewBox="0 0 800 800">
          <circle cx="400" cy="400" r="160" /><circle cx="400" cy="400" r="250" /><circle cx="400" cy="400" r="340" />
          <circle cx="400" cy="400" r="395" strokeDasharray="2 8" />
          <g className="orbit-spin"><circle className="sat" cx="400" cy="150" r="5" /><circle className="sat c" cx="740" cy="400" r="3.5" /></g>
          <g className="orbit-spin r"><circle className="sat c" cx="400" cy="240" r="4" /><circle className="sat" cx="60" cy="400" r="3" /></g>
        </svg>
      </div>
    </>
  );
}

export const Labels = ({ labels }: { labels: Record<string, string> }) => (
  <div className="row">
    {Object.entries(labels).map(([k, v]) => <span key={k} className="chip">{k}=<b>{v}</b></span>)}
  </div>
);

export function Callout({ kind, children }: { kind: 'warn' | 'bad' | 'ok' | 'acc'; children: ReactNode }) {
  return (
    <div className={`callout ${kind}`} role={kind === 'bad' ? 'alert' : undefined}>
      <Icon name={kind === 'acc' || kind === 'ok' ? 'info' : 'warn'} />
      <div>{children}</div>
    </div>
  );
}

export function Toggle({ checked, onChange, label, accent, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; accent?: boolean; disabled?: boolean }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} disabled={disabled} aria-label={label} onChange={e => onChange(e.target.checked)} />
      <span style={accent ? ({ '--on': 'var(--accent)' } as React.CSSProperties) : undefined} />
    </label>
  );
}

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: [T, string][]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, text]) => <button key={v} type="button" aria-pressed={v === value} onClick={() => onChange(v)}>{text}</button>)}
    </div>
  );
}

/** Chip list editor; Enter or comma adds, × removes. */
export function Tags({ values, onChange, placeholder, label, disabled }: { values: string[]; onChange: (v: string[]) => void; placeholder: string; label: string; disabled?: boolean }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setDraft('');
  };
  return (
    <div className="tags">
      {values.map(v => (
        <span key={v} className="chip mono">{v}{!disabled && <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter(x => x !== v))}>×</button>}</span>
      ))}
      {!disabled && (
        <input aria-label={label} placeholder={placeholder} value={draft} onChange={e => setDraft(e.target.value)} onBlur={add}
          onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); } else if (e.key === 'Backspace' && !draft && values.length) onChange(values.slice(0, -1)); }} />
      )}
    </div>
  );
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn sm copy" onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

const palette = ['#5b5bf0', '#0ea5b7', '#14a36b', '#c98a06', '#8b5cf6', '#e0568b'];
export function Who({ name, bad }: { name: string; bad?: boolean }) {
  const h = [...name].reduce((a, c) => a + c.charCodeAt(0), 0);
  return <div className="who" style={{ background: bad ? '#d93d4a' : palette[h % palette.length] }} aria-hidden="true">{initials(name)}</div>;
}
export const initials = (n: string) => n.split(/[.\s_-]/).filter(Boolean).map(p => p[0]).join('').slice(0, 2).toUpperCase();

export const Empty = ({ children }: { children: ReactNode }) => <div className="card pad small text-center">{children}</div>;
