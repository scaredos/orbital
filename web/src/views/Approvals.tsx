import { useState } from 'react';
import { ago, api, can, dur, stepUp, useMe, usePoll, type Approval } from '../api';
import { Empty, Who } from '../ui';

export function Approvals() {
  const me = useMe();
  const [items, error, reload] = usePoll<Approval[]>('/v1/approvals', 4000);
  const [done, setDone] = useState<Record<string, string>>({});
  const [failed, setFailed] = useState<Record<string, string>>({});

  const act = async (a: Approval, action: 'approve' | 'deny' | 'review' | 'kill') => {
    if ((action === 'approve' || action === 'deny') && !me.fresh) return stepUp();
    try {
      if (action === 'kill') await api(`/v1/sessions/${a.live_session}/kill`, 'POST');
      else await api(`/v1/grants/${a.id}/${action}`, 'POST');
      setDone(d => ({ ...d, [a.id]: { approve: 'Approved · grant issued', deny: 'Denied', review: 'Reviewed', kill: 'Session killed' }[action] }));
      setTimeout(reload, 1200);
    } catch (e) { setFailed(f => ({ ...f, [a.id]: (e as Error).message })); }
  };

  return (
    <>
      <div className="head rise"><div><h1>Approvals</h1>
        <p className="sub">Requests that need your sign-off, then break-glass sessions to review. {me.fresh ? '' : 'Approving asks you to re-authenticate with SSO.'}</p></div></div>
      {error && <p className="small" style={{ color: 'var(--bad)' }}>{error}</p>}
      <div className="grid gap-4">
        {items?.map((a, i) => (
          <article key={a.id} className={`card pad req rise ${a.emergency ? 'emerg' : ''}`} style={{ '--i': i + 1 } as React.CSSProperties}>
            <Who name={a.user} bad={a.emergency} />
            <div>
              <div className="row">
                <b>{a.user}</b>
                {a.emergency ? <span className="chip bad">BREAK-GLASS · self-approved {ago(a.created_at)}</span> : <span className="chip warn">pending · {ago(a.created_at).replace(' ago', '')}</span>}
                <span className="chip">rule {a.rule}</span>
              </div>
              <div className="small">ssh as <b>{a.login}</b> → <b>{a.node}</b> · {dur(a.ttl_secs)}</div>
              <div className="quote">"{a.reason}"</div>
              {a.live_session && <div className="row"><span className="dot live" /><span className="small">Session live · recording</span></div>}
              {failed[a.id] && <div className="small" style={{ color: 'var(--bad)' }}>{failed[a.id]}</div>}
            </div>
            <div className="acts row">
              {done[a.id] ? <span className={`chip ${/Denied|killed/.test(done[a.id]) ? 'bad' : 'ok'}`}>{done[a.id]}</span> : a.emergency ? (
                <>
                  {a.live_session && can(me, 'recordings:view') && <a className="btn sm" href={`#live/${a.live_session}`}>Watch live</a>}
                  <button className="btn sm ok" onClick={() => act(a, 'review')}>Mark reviewed</button>
                  {a.live_session && can(me, 'sessions:kill') && <button className="btn sm danger" onClick={() => act(a, 'kill')}>Kill session</button>}
                </>
              ) : a.user === me.username ? <span className="small">Your request</span> : (
                <>
                  <button className="btn sm danger" onClick={() => act(a, 'deny')}>Deny</button>
                  <button className="btn sm primary" onClick={() => act(a, 'approve')}>Approve {dur(a.ttl_secs)}</button>
                </>
              )}
            </div>
          </article>
        ))}
        {items && !items.length && <Empty>Nothing waiting for you.</Empty>}
      </div>
    </>
  );
}
