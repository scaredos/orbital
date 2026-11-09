//! Portal: embedded static build of web/, browser SSH terminal and read-only live view (WebSockets).
//!
//! The browser terminal runs an in-process SSH client against the same relay `orbital ssh` uses, so
//! browser sessions get the same upstream cert, recording, audit, revocation and live view.

use crate::{
    api::usable_grant,
    auth::{err, ApiResult, User},
    ssh::{self, Feed},
    AppRef,
};
use anyhow::{bail, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use russh::{client, keys::PublicKeyOrCertificate, ChannelMsg, Disconnect};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Dist;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
                   connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub async fn asset(uri: Uri) -> Response {
    let path = match uri.path().trim_start_matches('/') {
        "" => "index.html",
        p => p,
    };
    let Some(f) = Dist::get(path) else {
        return match path {
            "index.html" => (StatusCode::SERVICE_UNAVAILABLE, "portal not built: run `npm ci && npm run build` in web/").into_response(),
            _ => (StatusCode::NOT_FOUND, "not found").into_response(),
        };
    };
    // vite puts content-hashed files under assets/
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    (
        [
            (header::CONTENT_TYPE, f.metadata.mimetype().to_string()),
            (header::CACHE_CONTROL, cache.into()),
            (header::CONTENT_SECURITY_POLICY, CSP.into()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
            (header::REFERRER_POLICY, "no-referrer".into()),
        ],
        f.data,
    )
        .into_response()
}

/// WebSockets aren't covered by CORS; SameSite=Strict plus an exact Origin match keeps other sites out.
fn check_origin(app: &AppRef, headers: &HeaderMap) -> ApiResult<()> {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if origin == Some(app.cfg.public_url.trim_end_matches('/')) {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "websocket origin does not match the portal URL"))
    }
}

// ---------------------------------------------------------------- browser terminal

#[derive(Deserialize)]
pub struct TermQuery {
    grant: Uuid,
    #[serde(default = "cols")]
    cols: u32,
    #[serde(default = "rows")]
    rows: u32,
}
fn cols() -> u32 {
    80
}
fn rows() -> u32 {
    24
}

/// Wire format: binary frames carry terminal bytes both ways; text frames carry JSON control
/// messages: client `{"resize":[cols,rows]}`, server `{"session":id}`, `{"viewers":[names]}`, `{"closed":reason}`.
pub async fn terminal(State(app): State<AppRef>, user: User, headers: HeaderMap, Query(q): Query<TermQuery>, ws: WebSocketUpgrade) -> ApiResult<Response> {
    check_origin(&app, &headers)?;
    let g = usable_grant(&app, &user, q.grant).await?;
    Ok(ws.on_upgrade(move |mut sock| async move {
        let sid = Uuid::new_v4();
        let why = match run_terminal(app, &mut sock, g, user, sid, q.cols, q.rows).await {
            Ok(()) => "closed".to_string(),
            Err(e) => format!("{e:#}"),
        };
        let _ = sock.send(Message::Text(json!({"closed": why}).to_string().into())).await;
    }))
}

struct Local;
impl client::Handler for Local {
    type Error = russh::Error;
    // in-process duplex to our own relay
    async fn check_server_key(&mut self, _k: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn run_terminal(app: AppRef, sock: &mut WebSocket, g: ssh::GrantRow, user: User, sid: Uuid, cols: u32, rows: u32) -> Result<()> {
    let (relay_end, client_end) = tokio::io::duplex(1 << 16);
    let login = g.login.clone();
    tokio::spawn(ssh::serve_connection(app.clone(), relay_end, g, user, sid, true));
    let mut c = client::connect_stream(Arc::new(client::Config::default()), client_end, Local).await?;
    if !c.authenticate_none(login).await?.success() {
        bail!("relay refused the session (see audit log)");
    }
    let ch = c.channel_open_session().await?;
    ch.request_pty(false, "xterm-256color", cols.clamp(10, 500), rows.clamp(5, 200), 0, 0, &[]).await?;
    ch.request_shell(false).await?;
    sock.send(Message::Text(json!({"session": sid}).to_string().into())).await?;
    // registered by the relay once upstream auth succeeded (before the channel opened)
    let feed = app.live.lock().await.get(&sid).map(|l| l.feed.clone());
    let mut viewers = feed.as_ref().map(|f| f.viewers.subscribe());
    let (mut rd, wr) = ch.split();
    loop {
        tokio::select! {
            m = sock.recv() => match m {
                Some(Ok(Message::Binary(b))) => wr.data_bytes(b).await?,
                Some(Ok(Message::Text(t))) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                        if let (Some(c), Some(r)) = (v["resize"][0].as_u64(), v["resize"][1].as_u64()) {
                            wr.window_change(c.clamp(10, 500) as u32, r.clamp(5, 200) as u32, 0, 0).await?;
                        }
                    }
                }
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
            },
            m = rd.wait() => match m {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => sock.send(Message::Binary(data)).await?,
                None | Some(ChannelMsg::Close) => break,
                Some(_) => {}
            },
            Some(names) = async { match &mut viewers {
                Some(v) => v.changed().await.ok().map(|_| v.borrow_and_update().clone()),
                None => std::future::pending().await,
            } } => sock.send(Message::Text(json!({"viewers": names}).to_string().into())).await?,
        }
    }
    let _ = c.disconnect(Disconnect::ByApplication, "", "en").await;
    Ok(())
}

// ---------------------------------------------------------------- live view

/// Read-only fan-out of a live session (input from the viewer is ignored). Needs `recordings:view` on the node.
pub async fn live(State(app): State<AppRef>, user: User, headers: HeaderMap, Path(sid): Path<Uuid>, ws: WebSocketUpgrade) -> ApiResult<Response> {
    check_origin(&app, &headers)?;
    let row: Option<(sqlx::types::Json<BTreeMap<String, String>>, String, String)> = sqlx::query_as(
        "SELECT coalesce(n.labels, '{}'), s.replica, s.username FROM sessions s LEFT JOIN nodes n ON n.id = s.node_id
         WHERE s.id = $1 AND s.ended_at IS NULL",
    )
    .bind(sid)
    .fetch_optional(&app.db)
    .await?;
    let (labels, replica, owner) = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "no live session with that id"))?;
    user.require_for("recordings:view", &labels)?;
    if replica != app.cfg.replica_id {
        // ponytail: no cross-replica fan-out; open the portal on the replica that holds the session
        return Err(err(StatusCode::CONFLICT, format!("session runs on replica {replica}")));
    }
    let feed = app.live.lock().await.get(&sid).map(|l| l.feed.clone()).ok_or_else(|| err(StatusCode::NOT_FOUND, "session is not live"))?;
    app.audit("session.viewed_live", "info", Some(&user.username), json!({"session": sid, "user": owner})).await;
    Ok(ws.on_upgrade(move |sock| run_live(feed, sock, user.username)))
}

async fn run_live(feed: Arc<Feed>, mut sock: WebSocket, name: String) {
    feed.viewers.send_modify(|v| v.push(name.clone()));
    let (back, mut rx) = feed.subscribe();
    let mut ok = sock.send(Message::Binary(back.into())).await.is_ok();
    while ok {
        tokio::select! {
            _ = feed.done.cancelled() => break,
            m = rx.recv() => match m {
                Ok(d) => ok = sock.send(Message::Binary(d.into())).await.is_ok(),
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            m = sock.recv() => if matches!(m, None | Some(Err(_)) | Some(Ok(Message::Close(_)))) { break },
        }
    }
    feed.viewers.send_modify(|v| {
        if let Some(i) = v.iter().position(|x| x == &name) {
            v.remove(i);
        }
    });
    let _ = sock.send(Message::Text(json!({"closed": "session ended"}).to_string().into())).await;
}
