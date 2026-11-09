import { createContext, useCallback, useContext, useEffect, useState } from 'react';

export type Perm = { perm: string; team?: string };
export type Me = {
  id: string; username: string; groups: string[]; permissions: Perm[];
  csrf?: string; fresh: boolean; sso: boolean; replica: string;
};
export type Node = {
  name: string; labels: Record<string, string>; services: Record<string, number>;
  last_seen: string | null; version: string | null; cert_expires_at: string; online: boolean; stale: boolean;
};
export type Grant = {
  id: string; user_id: string; node_id: string; node_name: string; service: string; login: string; reason: string;
  status: 'pending' | 'approved' | 'denied' | 'revoked'; emergency: boolean; expires_at: string | null;
  node_labels: Record<string, string>; username: string; created_at: string; reviewed_by: string | null;
};
export type Approval = {
  id: string; user: string; node: string; login: string; reason: string; rule: string; status: string;
  emergency: boolean; ttl_secs: number; created_at: string; live_session: string | null;
};
export type FileOp = { id: number; op: string; path: string; path2: string | null; bytes: number; at: string };
export type Session = {
  id: string; grant_id: string | null; node_name: string; username: string; login: string; protocol: string; replica: string;
  emergency: boolean; started_at: string; ended_at: string | null; end_reason: string | null; recording_sha256: string | null;
  reason: string | null; files: FileOp[];
};
export type AuditEvent = { id: number; at: string; kind: string; severity: string; actor: string | null; data: Record<string, unknown> };
export type Rule = {
  name: string; groups: string[]; node_labels: Record<string, string>; services: string[]; logins: string[];
  require_approval: boolean; emergency: boolean; max_ttl_secs: number;
};

let csrf = '';
export const setCsrf = (t = '') => { csrf = t; };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T = unknown>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', 'x-orbital-csrf': csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && j.error === 'step_up_required') stepUp();
    // session expired (8h / 30 min idle): back to the sign-in screen
    else if (r.status === 401 && !path.startsWith('/v1/me') && !path.startsWith('/v1/auth/')) location.reload();
    throw new ApiError(r.status, j.error ?? `HTTP ${r.status}`);
  }
  return j as T;
}

/** Re-authenticate with the IdP (max_age=300) and come back to the current screen. */
export function stepUp() {
  location.href = `/v1/auth/login?step_up=true&return_to=${encodeURIComponent(location.hash.slice(1))}`;
}

export const can = (me: Me, perm: string) => me.permissions.some(p => p.perm === perm);

/** GET `path` now and every `ms`; null path = skip. */
export function usePoll<T>(path: string | null, ms = 5000): [T | undefined, string | undefined, () => void] {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const load = useCallback(() => {
    if (!path) return;
    api<T>(path).then(d => { setData(d); setError(undefined); }, e => setError(String(e.message)));
  }, [path]);
  useEffect(() => {
    load();
    if (!ms) return;
    const t = setInterval(load, ms);
    return () => clearInterval(t);
  }, [load, ms]);
  return [data, error, load];
}

export function ago(ts: string | null | undefined): string {
  if (!ts) return 'never';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 10) return 'now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const dur = (secs: number) =>
  secs >= 3600 ? `${+(secs / 3600).toFixed(1)}h` : secs >= 60 ? `${Math.round(secs / 60)} min` : `${secs}s`;

export const clock = (ts: string) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export const wsUrl = (path: string) => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`;

const MeCtx = createContext<Me>(null!);
export const MeProvider = MeCtx.Provider;
export const useMe = () => useContext(MeCtx);
export const SearchCtx = createContext('');
