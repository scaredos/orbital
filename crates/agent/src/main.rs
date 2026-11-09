//! orbital-agent: `install` (reads its own trailer, enrolls, sets up systemd + sshd), `run` (daemon), `uninstall`.

mod install;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use orbital_proto::{mux, now, read_msg, verify_grant, write_msg, Control, GrantClaims, Hello, HelloReply, StreamOpen, StreamReply};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsConnector;

#[derive(Parser)]
#[command(name = "orbital-agent", version, about = "Orbital node agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll this host and install the agent (run once, as root)
    Install(install::InstallArgs),
    /// Run the agent daemon
    Run {
        #[arg(long, default_value = "/etc/orbital")]
        config_dir: PathBuf,
    },
    /// Remove the agent, its service, config and sshd integration
    Uninstall {
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub node_id: String,
    pub name: String,
    pub orch_urls: Vec<String>,
    pub services: BTreeMap<String, u16>,
    /// hex ed25519 key that signs per-stream grant tokens
    pub grant_key: String,
    pub cert_not_after: u64,
    pub state_dir: PathBuf,
}

impl AgentConfig {
    pub fn load(dir: &Path) -> Result<Self> {
        let p = dir.join("config.toml");
        Ok(toml::from_str(&std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?)?)
    }
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_atomic(&dir.join("config.toml"), toml::to_string(self)?.as_bytes())
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn server_name(url: &str) -> Result<ServerName<'static>> {
    let host = url.rsplit_once(':').map(|(h, _)| h).unwrap_or(url).trim_start_matches('[').trim_end_matches(']');
    Ok(ServerName::try_from(host.to_string())?)
}

pub async fn tls_connect(url: &str, cfg: rustls::ClientConfig) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(url)).await.context("connect timeout")??;
    tcp.set_nodelay(true)?;
    Ok(TlsConnector::from(Arc::new(cfg)).connect(server_name(url)?, tcp).await?)
}

fn client_tls(dir: &Path) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::fs::read(dir.join("ca.crt"))?.as_slice()) {
        roots.add(c?)?;
    }
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut std::fs::read(dir.join("agent.crt"))?.as_slice()).collect::<Result<_, _>>()?;
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut std::fs::read(dir.join("agent.key"))?.as_slice())?.context("agent.key")?;
    Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_client_auth_cert(certs, key)?)
}

pub fn new_csr() -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())?.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

// ---------------------------------------------------------------- daemon

struct Agent {
    dir: PathBuf,
    cfg: Mutex<AgentConfig>,
    grant_key: ed25519_dalek::VerifyingKey,
    dialing: Mutex<HashSet<String>>,
}

fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    match cli.cmd {
        Cmd::Install(a) => rt.block_on(install::install(a)),
        Cmd::Uninstall { yes } => install::uninstall(yes),
        Cmd::Run { config_dir } => rt.block_on(run(config_dir)),
    }
}

async fn run(dir: PathBuf) -> Result<()> {
    let cfg = AgentConfig::load(&dir)?;
    let gk: [u8; 32] = hex::decode(&cfg.grant_key)?.try_into().map_err(|_| anyhow::anyhow!("bad grant_key"))?;
    std::fs::create_dir_all(&cfg.state_dir).ok();
    let agent = Arc::new(Agent {
        grant_key: ed25519_dalek::VerifyingKey::from_bytes(&gk)?,
        dir,
        dialing: Mutex::default(),
        cfg: Mutex::new(cfg.clone()),
    });
    eprintln!("orbital-agent {} node {} ({}) starting", orbital_proto::VERSION, cfg.name, cfg.node_id);
    for url in cfg.orch_urls {
        spawn_dialer(&agent, url);
    }
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// One tunnel per replica: orchestrators route through whichever replica holds a tunnel to us.
fn spawn_dialer(agent: &Arc<Agent>, url: String) {
    if !agent.dialing.lock().unwrap().insert(url.clone()) {
        return;
    }
    let agent = agent.clone();
    tokio::spawn(async move {
        loop {
            match tunnel(&agent, &url).await {
                Ok(()) => eprintln!("[{url}] tunnel closed"),
                Err(e) => eprintln!("[{url}] tunnel error: {e:#}"),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn tunnel(agent: &Arc<Agent>, url: &str) -> Result<()> {
    let mut tls = tls_connect(url, client_tls(&agent.dir)?).await?;
    let services = agent.cfg.lock().unwrap().services.clone();
    write_msg(&mut tls, &Hello::Connect { version: orbital_proto::VERSION.into(), services }).await?;
    match read_msg::<_, HelloReply>(&mut tls).await? {
        HelloReply::Ok => {}
        HelloReply::Error { msg } => bail!("orchestrator rejected us: {msg}"),
        other => bail!("unexpected reply {other:?}"),
    }
    eprintln!("[{url}] tunnel up");
    let (m, mut inbound) = mux::spawn(tls, mux::Mode::Client);
    let ctrl = m.open().await?;
    let (mut r, mut w) = tokio::io::split(ctrl);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Control>>(8);
    tokio::spawn(async move {
        loop {
            let msg = read_msg::<_, Control>(&mut r).await;
            let stop = msg.is_err();
            if tx.send(msg).await.is_err() || stop {
                break;
            }
        }
    });
    write_msg(&mut w, &Control::Heartbeat).await?;

    // Rotate well before the 30d expiry; the new key only replaces the old one once the cert arrives.
    let mut pending_key = None;
    if agent.cfg.lock().unwrap().cert_not_after < now() + 10 * 86400 {
        let (key, csr) = new_csr()?;
        pending_key = Some(key);
        write_msg(&mut w, &Control::Renew { csr_pem: csr }).await?;
    }

    let mut hb = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = hb.tick() => write_msg(&mut w, &Control::Heartbeat).await?,
            s = inbound.recv() => {
                let s = s.context("connection closed")?;
                let agent = agent.clone();
                tokio::spawn(async move {
                    let (node_id, services, log) = {
                        let c = agent.cfg.lock().unwrap();
                        (c.node_id.clone(), c.services.clone(), c.state_dir.join("access.log"))
                    };
                    if let Err(e) = handle_stream(s, &agent.grant_key, &node_id, &services, &log).await {
                        eprintln!("stream: {e:#}");
                    }
                });
            }
            m = rx.recv() => match m.context("control stream closed")?? {
                Control::Replicas { urls } => {
                    let mut c = agent.cfg.lock().unwrap().clone();
                    let mut changed = false;
                    for u in urls {
                        if !c.orch_urls.contains(&u) { c.orch_urls.push(u.clone()); changed = true; }
                        spawn_dialer(agent, u);
                    }
                    if changed { c.save(&agent.dir).ok(); *agent.cfg.lock().unwrap() = c; }
                }
                Control::Renewed { cert_pem, not_after } => {
                    let Some(key) = pending_key.take() else { continue };
                    write_atomic(&agent.dir.join("agent.key"), key.as_bytes())?;
                    write_atomic(&agent.dir.join("agent.crt"), cert_pem.as_bytes())?;
                    let mut c = agent.cfg.lock().unwrap();
                    c.cert_not_after = not_after;
                    c.save(&agent.dir)?;
                    eprintln!("certificate rotated, valid until {not_after}");
                }
                _ => {}
            },
        }
    }
}

/// Verifies the orchestrator-signed grant token and the local service allowlist.
fn authorize(key: &ed25519_dalek::VerifyingKey, node_id: &str, services: &BTreeMap<String, u16>, token: &str) -> Result<(GrantClaims, u16)> {
    let c = verify_grant(key, token, now())?;
    if c.node_id != node_id {
        bail!("grant is for node {}", c.node_id);
    }
    let port = *services.get(&c.service).with_context(|| format!("service {:?} is not exposed on this node", c.service))?;
    Ok((c, port))
}

fn access_log(path: &Path, entry: serde_json::Value) {
    eprintln!("access {entry}");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = writeln!(f, "{entry}");
    }
}

async fn handle_stream<S>(mut s: S, key: &ed25519_dalek::VerifyingKey, node_id: &str, services: &BTreeMap<String, u16>, log: &Path) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let open: StreamOpen = tokio::time::timeout(Duration::from_secs(10), read_msg(&mut s)).await??;
    let (claims, port) = match authorize(key, node_id, services, &open.token) {
        Ok(v) => v,
        Err(e) => {
            access_log(log, serde_json::json!({"at": now(), "ok": false, "error": format!("{e:#}")}));
            write_msg(&mut s, &StreamReply { ok: false, error: Some(format!("{e:#}")) }).await?;
            return Ok(());
        }
    };
    let entry = serde_json::json!({"at": now(), "ok": true, "grant": claims.grant_id, "user": claims.user, "service": claims.service});
    let mut local = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(t) => t,
        Err(e) => {
            access_log(log, serde_json::json!({"at": now(), "ok": false, "grant": claims.grant_id, "error": e.to_string()}));
            write_msg(&mut s, &StreamReply { ok: false, error: Some(format!("connect 127.0.0.1:{port}: {e}")) }).await?;
            return Ok(());
        }
    };
    access_log(log, entry);
    write_msg(&mut s, &StreamReply { ok: true, error: None }).await?;
    let _ = tokio::io::copy_bidirectional(&mut s, &mut local).await;
    let _ = s.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use orbital_proto::sign_grant;

    fn claims(node: &str, svc: &str) -> GrantClaims {
        GrantClaims { grant_id: "g1".into(), node_id: node.into(), service: svc.into(), user: "alice".into(), exp: now() + 60 }
    }

    #[test]
    fn local_allowlist_and_node_binding() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let services: BTreeMap<String, u16> = [("ssh".to_string(), 22)].into();
        assert_eq!(authorize(&k.verifying_key(), "n1", &services, &sign_grant(&k, &claims("n1", "ssh"))).unwrap().1, 22);
        assert!(authorize(&k.verifying_key(), "n1", &services, &sign_grant(&k, &claims("n1", "postgres"))).is_err());
        assert!(authorize(&k.verifying_key(), "n1", &services, &sign_grant(&k, &claims("n2", "ssh"))).is_err());
    }

    #[tokio::test]
    async fn forged_stream_is_refused_and_logged() {
        let real = SigningKey::from_bytes(&[1; 32]);
        let forger = SigningKey::from_bytes(&[2; 32]);
        let services: BTreeMap<String, u16> = [("ssh".to_string(), 22)].into();
        let log = std::env::temp_dir().join(format!("orbital-access-{}.log", std::process::id()));
        let (mut orch, agent_side) = tokio::io::duplex(4096);
        let vk = real.verifying_key();
        let task = tokio::spawn({
            let log = log.clone();
            async move { handle_stream(agent_side, &vk, "n1", &services, &log).await }
        });
        write_msg(&mut orch, &StreamOpen { token: sign_grant(&forger, &claims("n1", "ssh")) }).await.unwrap();
        let reply: StreamReply = read_msg(&mut orch).await.unwrap();
        assert!(!reply.ok);
        assert!(reply.error.unwrap().contains("signature"));
        task.await.unwrap().unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("\"ok\":false") && logged.contains("signature"));
        let _ = std::fs::remove_file(log);
    }
}
