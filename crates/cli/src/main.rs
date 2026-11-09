//! orbital: login (OIDC loopback / break-glass), ssh, proxy (ProxyCommand), setup, and admin helpers.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use russh::keys::{ssh_key::LineEnding, Algorithm, PrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "orbital", version, about = "Orbital zero-trust access CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign in (browser SSO), create/refresh this device's key and SSH certificate
    Login {
        /// Orchestrator URL, e.g. https://orbital.example.com (remembered)
        url: Option<String>,
        /// PEM CA to trust for the orchestrator (when it uses its self-issued cert)
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Break-glass local admin login (password from ORBITAL_ADMIN_PASSWORD or prompt)
        #[arg(long)]
        local: bool,
    },
    /// SSH to a node through Orbital: orbital ssh [login@]node [-- command]
    Ssh {
        target: String,
        #[arg(short, long, env = "ORBITAL_REASON")]
        reason: Option<String>,
        /// Break-glass: self-approve on rules that allow emergency access
        #[arg(long)]
        emergency: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// ProxyCommand for OpenSSH: pipes stdin/stdout to the orchestrator's SSH relay
    Proxy {
        #[arg(long)]
        grant: Option<String>,
        /// login@node or login@node.orbital (when used from ~/.ssh/config)
        target: Option<String>,
    },
    /// Add a `Host *.orbital` block to ~/.ssh/config so plain ssh/scp/sftp/rsync work
    Setup,
    /// List nodes
    Ls,
    /// Node admin
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Pending access requests
    Approvals,
    Approve { id: String },
    Deny { id: String },
    /// Revoke a grant (kills its live sessions)
    Revoke { id: String },
    /// Show or replace the policy (JSON array of rules)
    Policy {
        /// file to upload; omit to print the current policy
        file: Option<PathBuf>,
    },
    Sessions,
    Kill { id: String },
    Audit {
        #[arg(long, default_value = "50")]
        limit: u32,
        #[arg(long)]
        kind: Option<String>,
    },
    Devices {
        /// device id to revoke
        #[arg(long)]
        revoke: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Mint a join token and print the install one-liner
    Add,
    Rm { name: String },
}

// ---------------------------------------------------------------- local state

#[derive(Serialize, Deserialize, Default)]
struct Config {
    url: String,
    ca_pem: Option<String>,
    token: Option<String>,
    username: Option<String>,
}

fn home() -> PathBuf {
    if let Ok(h) = std::env::var("ORBITAL_HOME") {
        return h.into();
    }
    let h = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(h).join(".orbital")
}
fn path(name: &str) -> PathBuf {
    home().join(name)
}

fn write_private(p: &PathBuf, data: &[u8]) -> Result<()> {
    std::fs::create_dir_all(home())?;
    std::fs::write(p, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

impl Config {
    fn load() -> Config {
        let mut c: Config = std::fs::read(path("config.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        if let Ok(u) = std::env::var("ORBITAL_URL") {
            c.url = u;
        }
        c
    }
    fn save(&self) -> Result<()> {
        write_private(&path("config.json"), &serde_json::to_vec_pretty(self)?)
    }
    fn http(&self) -> Result<reqwest::Client> {
        let mut b = reqwest::Client::builder().http1_only().connect_timeout(Duration::from_secs(10));
        if let Some(pem) = &self.ca_pem {
            b = b.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
        }
        Ok(b.build()?)
    }
}

struct Unauthorized;
impl std::fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "not signed in or session expired: run `orbital login`")
    }
}
impl std::fmt::Debug for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Unauthorized {}

async fn api(method: reqwest::Method, p: &str, body: Option<Value>) -> Result<Value> {
    let c = Config::load();
    if c.url.is_empty() {
        bail!("no orchestrator configured: run `orbital login <url>`");
    }
    let mut req = c.http()?.request(method, format!("{}{p}", c.url));
    if let Some(t) = &c.token {
        req = req.bearer_auth(t);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Unauthorized.into());
    }
    if !status.is_success() {
        bail!("{}: {}", status, v["error"].as_str().unwrap_or("request failed"));
    }
    Ok(v)
}

/// Retries once after an interactive re-login when the token or IdP session expired.
async fn api_relogin(method: reqwest::Method, p: &str, body: Option<Value>) -> Result<Value> {
    match api(method.clone(), p, body.clone()).await {
        Err(e) if e.is::<Unauthorized>() && std::env::var("ORBITAL_NO_RELOGIN").is_err() => {
            eprintln!("session expired, signing in again...");
            login(None, None, false).await?;
            api(method, p, body).await
        }
        r => r,
    }
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

// ---------------------------------------------------------------- login

fn device_key() -> Result<PrivateKey> {
    let p = path("device_key");
    if let Ok(pem) = std::fs::read_to_string(&p) {
        return Ok(PrivateKey::from_openssh(&pem)?);
    }
    // ponytail: file-backed device key; TPM / Secure Enclave non-exportable keys are the upgrade path
    let k = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    write_private(&p, k.to_openssh(LineEnding::LF)?.as_bytes())?;
    write_private(&path("device_key.pub"), k.public_key().to_openssh()?.as_bytes())?;
    Ok(k)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "device".into())
}

fn open_browser(url: &str) {
    if std::env::var("ORBITAL_BROWSER").as_deref() == Ok("none") {
        return;
    }
    let _ = if cfg!(windows) {
        std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).stderr(std::process::Stdio::null()).spawn()
    };
}

async fn wait_for_callback(listener: tokio::net::TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut s, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = s.read(&mut buf).await?;
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = req.split_whitespace().nth(1).unwrap_or("");
        let q: BTreeMap<String, String> = target
            .split_once('?')
            .map(|(_, q)| q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect())
            .unwrap_or_default();
        let ok = q.get("state").map(String::as_str) == Some(state) && q.contains_key("code");
        let msg = if ok { "Signed in to Orbital. You can close this tab." } else { "Unexpected request." };
        let _ = s
            .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{msg}", msg.len()).as_bytes())
            .await;
        if ok {
            return Ok(q["code"].clone());
        }
    }
}

async fn login(url: Option<String>, ca: Option<PathBuf>, local: bool) -> Result<()> {
    let mut c = Config::load();
    if let Some(u) = url {
        c.url = u.trim_end_matches('/').to_string();
    }
    if let Some(ca) = ca {
        c.ca_pem = Some(std::fs::read_to_string(ca)?);
    }
    if c.url.is_empty() {
        bail!("usage: orbital login <orchestrator url>");
    }
    let key = device_key()?;
    let mut body = json!({"device_pubkey": key.public_key().to_openssh()?, "device_name": hostname()});
    if local {
        let pw = match std::env::var("ORBITAL_ADMIN_PASSWORD") {
            Ok(p) => p,
            Err(_) => prompt_tty("break-glass admin password: ")?,
        };
        body["password"] = json!(pw);
    } else {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let state = hex(&rand::random::<[u8; 16]>());
        let login_url = format!("{}/v1/auth/login?cli_port={port}&cli_state={state}", c.url);
        eprintln!("Opening your browser to sign in. If it doesn't open, visit:\n  {login_url}");
        open_browser(&login_url);
        let code = tokio::time::timeout(Duration::from_secs(600), wait_for_callback(listener, &state)).await.context("login timed out")??;
        body["code"] = json!(code);
    }
    let resp = c.http()?.post(format!("{}/v1/auth/exchange", c.url)).json(&body).send().await?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("login failed: {}", v["error"].as_str().unwrap_or(status.as_str()));
    }
    write_private(&path("device_key-cert.pub"), v["ssh_cert"].as_str().context("ssh_cert")?.as_bytes())?;
    write_private(&path("known_hosts"), format!("{}\n", v["known_hosts"].as_str().context("known_hosts")?).as_bytes())?;
    c.token = v["token"].as_str().map(str::to_string);
    c.username = v["username"].as_str().map(str::to_string);
    c.save()?;
    eprintln!("signed in as {}", c.username.as_deref().unwrap_or("?"));
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Reads a line from the controlling terminal (stdin/stdout may be ssh's pipes).
fn prompt_tty(msg: &str) -> Result<String> {
    let (inp, out) = if cfg!(windows) { ("CONIN$", "CONOUT$") } else { ("/dev/tty", "/dev/tty") };
    let mut o = std::fs::OpenOptions::new().write(true).open(out).context("no terminal to prompt on; pass --reason or set ORBITAL_REASON")?;
    write!(o, "{msg}")?;
    o.flush()?;
    let mut line = String::new();
    std::io::BufReader::new(std::fs::File::open(inp)?).read_line(&mut line)?;
    Ok(line.trim().to_string())
}

// ---------------------------------------------------------------- grants

#[derive(Serialize, Deserialize, Default)]
struct GrantCache(BTreeMap<String, String>);

fn split_target(t: &str) -> (Option<String>, String) {
    let (login, host) = match t.split_once('@') {
        Some((l, h)) => (Some(l.to_string()), h),
        None => (None, t),
    };
    (login, host.trim_end_matches(".orbital").to_string())
}

/// Reuses a cached approved grant for login@node or requests a new one (prompting for the reason).
async fn get_grant(node: &str, login: Option<String>, reason: Option<String>, emergency: bool) -> Result<String> {
    let login = login.or_else(|| Config::load().username).context("not signed in: run `orbital login`")?;
    let key = format!("{login}@{node}");
    let mut cache: GrantCache = std::fs::read(path("grants.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if let Some(id) = cache.0.get(&key) {
        if let Ok(g) = api(reqwest::Method::GET, &format!("/v1/grants/{id}"), None).await {
            let fresh = g["expires_at"].as_str().and_then(|e| chrono_secs_left(e)).unwrap_or(0) > 30;
            if g["status"] == "approved" && fresh {
                return Ok(id.clone());
            }
        }
    }
    let reason = match reason {
        Some(r) if !r.trim().is_empty() => r,
        _ => prompt_tty(&format!("Reason for accessing {key}: "))?,
    };
    let mut g = api_relogin(reqwest::Method::POST, "/v1/grants", Some(json!({"node": node, "login": login, "reason": reason, "emergency": emergency}))).await?;
    let id = g["id"].as_str().context("grant id")?.to_string();
    if g["status"] == "pending" {
        eprintln!("access to {key} needs approval; request {id} is waiting for an approver...");
        let deadline = std::time::Instant::now() + Duration::from_secs(1800);
        while g["status"] == "pending" {
            if std::time::Instant::now() > deadline {
                bail!("still pending after 30 minutes");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            g = api(reqwest::Method::GET, &format!("/v1/grants/{id}"), None).await?;
        }
    }
    if g["status"] != "approved" {
        bail!("request {id} was {}", g["status"].as_str().unwrap_or("?"));
    }
    if g["emergency"] == true {
        eprintln!("EMERGENCY ACCESS: this session is flagged and will be reviewed");
    }
    cache.0.insert(key, id.clone());
    write_private(&path("grants.json"), &serde_json::to_vec(&cache)?)?;
    Ok(id)
}

fn chrono_secs_left(ts: &str) -> Option<i64> {
    Some((chrono::DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds())
}

// ---------------------------------------------------------------- ssh / proxy / setup

fn ssh_opts(exe_proxy: String) -> Vec<String> {
    let s = |p: &str| path(p).to_string_lossy().into_owned();
    vec![
        "-o".into(),
        format!("ProxyCommand={exe_proxy}"),
        "-o".into(),
        "HostKeyAlias=orbital".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", s("known_hosts")),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-i".into(),
        s("device_key"),
        "-o".into(),
        format!("CertificateFile={}", s("device_key-cert.pub")),
    ]
}

fn self_exe() -> Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().replace('\\', "/"))
}

async fn cmd_ssh(target: String, reason: Option<String>, emergency: bool, command: Vec<String>) -> Result<i32> {
    let (login, node) = split_target(&target);
    let login = login.or_else(|| Config::load().username).context("not signed in: run `orbital login`")?;
    let grant = get_grant(&node, Some(login.clone()), reason, emergency).await?;
    let mut args = ssh_opts(format!("\"{}\" proxy --grant {grant}", self_exe()?));
    args.extend(["-l".into(), login, node]);
    args.extend(command);
    let st = std::process::Command::new("ssh").args(&args).status().context("running ssh (is OpenSSH installed?)")?;
    Ok(st.code().unwrap_or(1))
}

async fn cmd_proxy(grant: Option<String>, target: Option<String>) -> Result<()> {
    let id = match (grant, target) {
        (Some(g), _) => g,
        (None, Some(t)) => {
            let (login, node) = split_target(&t);
            get_grant(&node, login, std::env::var("ORBITAL_REASON").ok(), false).await?
        }
        _ => bail!("usage: orbital proxy --grant <id> | <login@node>"),
    };
    let c = Config::load();
    let resp = c
        .http()?
        .get(format!("{}/v1/connect?grant={id}", c.url))
        .bearer_auth(c.token.as_deref().unwrap_or_default())
        .header("connection", "upgrade")
        .header("upgrade", "orbital-ssh")
        .send()
        .await?;
    if resp.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS {
        let s = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        bail!("orbital: {s}: {}", v["error"].as_str().unwrap_or("connect failed"));
    }
    let up = resp.upgrade().await?;
    let (mut r, mut w) = tokio::io::split(up);
    let a = async {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut w).await;
        let _ = w.shutdown().await;
    };
    let b = async {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut r, &mut stdout).await;
        let _ = stdout.flush().await;
    };
    tokio::select! { _ = a => {}, _ = b => {} }
    Ok(())
}

fn cmd_setup() -> Result<()> {
    let h = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).context("HOME")?;
    let dir = PathBuf::from(h).join(".ssh");
    std::fs::create_dir_all(&dir)?;
    let cfg_path = dir.join("config");
    let existing = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    if existing.contains("# >>> orbital") {
        println!("{} already has an Orbital block", cfg_path.display());
        return Ok(());
    }
    let opts = ssh_opts(format!("\"{}\" proxy %r@%h", self_exe()?));
    let mut block = String::from("\n# >>> orbital (managed by `orbital setup`)\nHost *.orbital\n");
    let mut it = opts.iter();
    while let Some(flag) = it.next() {
        let val = it.next().unwrap();
        let line = match flag.as_str() {
            "-i" => format!("IdentityFile \"{val}\""),
            _ => {
                let (k, v) = val.split_once('=').unwrap();
                format!("{k} {v}")
            }
        };
        block.push_str(&format!("    {line}\n"));
    }
    block.push_str("# <<< orbital\n");
    std::fs::write(&cfg_path, existing + &block)?;
    println!("added `Host *.orbital` to {}; try: ssh <login>@<node>.orbital", cfg_path.display());
    Ok(())
}

// ---------------------------------------------------------------- main

#[tokio::main]
async fn main() {
    let code = match run(Cli::parse()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("orbital: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    use reqwest::Method as M;
    match cli.cmd {
        Cmd::Login { url, ca, local } => login(url, ca, local).await?,
        Cmd::Ssh { target, reason, emergency, command } => return cmd_ssh(target, reason, emergency, command).await,
        Cmd::Proxy { grant, target } => cmd_proxy(grant, target).await?,
        Cmd::Setup => cmd_setup()?,
        Cmd::Ls => {
            let v = api_relogin(M::GET, "/v1/nodes", None).await?;
            for n in v.as_array().ok_or_else(|| anyhow!("bad response"))? {
                let labels: Vec<String> = n["labels"].as_object().map(|o| o.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect()).unwrap_or_default();
                let svcs: Vec<&String> = n["services"].as_object().map(|o| o.keys().collect()).unwrap_or_default();
                let st = if n["online"] == true { "online" } else if n["stale"] == true { "stale" } else { "offline" };
                println!("{:<24} {:<8} {:<30} {}", n["name"].as_str().unwrap_or(""), st, labels.join(","), svcs.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","));
            }
        }
        Cmd::Node { cmd: NodeCmd::Add } => {
            let v = api_relogin(M::POST, "/v1/nodes/join", None).await?;
            eprintln!("Join token (single use, expires in 1h). On the new host run:");
            println!("{}", v["command"].as_str().unwrap_or_default());
        }
        Cmd::Node { cmd: NodeCmd::Rm { name } } => print(&api_relogin(M::DELETE, &format!("/v1/nodes/{name}"), None).await?),
        Cmd::Approvals => print(&api_relogin(M::GET, "/v1/approvals", None).await?),
        Cmd::Approve { id } => print(&api_relogin(M::POST, &format!("/v1/grants/{id}/approve"), None).await?),
        Cmd::Deny { id } => print(&api_relogin(M::POST, &format!("/v1/grants/{id}/deny"), None).await?),
        Cmd::Revoke { id } => print(&api_relogin(M::POST, &format!("/v1/grants/{id}/revoke"), None).await?),
        Cmd::Policy { file: None } => print(&api_relogin(M::GET, "/v1/policy", None).await?),
        Cmd::Policy { file: Some(f) } => {
            let rules: Value = serde_json::from_slice(&std::fs::read(&f)?).context("policy file must be a JSON array of rules")?;
            print(&api_relogin(M::PUT, "/v1/policy", Some(rules)).await?)
        }
        Cmd::Sessions => print(&api_relogin(M::GET, "/v1/sessions", None).await?),
        Cmd::Kill { id } => print(&api_relogin(M::POST, &format!("/v1/sessions/{id}/kill"), None).await?),
        Cmd::Audit { limit, kind } => {
            let q = kind.map(|k| format!("&kind={k}")).unwrap_or_default();
            print(&api_relogin(M::GET, &format!("/v1/audit?limit={limit}{q}"), None).await?)
        }
        Cmd::Devices { revoke: Some(id) } => print(&api_relogin(M::DELETE, &format!("/v1/devices/{id}"), None).await?),
        Cmd::Devices { revoke: None } => print(&api_relogin(M::GET, "/v1/devices", None).await?),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets_and_time() {
        assert_eq!(split_target("deploy@web1.orbital"), (Some("deploy".into()), "web1".into()));
        assert_eq!(split_target("web1"), (None, "web1".into()));
        let left = chrono_secs_left("2000-01-01T00:00:00.123Z").unwrap();
        let expect = 946684800 - std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!((left - expect).abs() <= 1);
    }
}
