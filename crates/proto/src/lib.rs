//! Wire types shared by agent and orchestrator: binary trailer, length-prefixed JSON framing,
//! control/enrollment messages, signed per-stream grant tokens, and a tokio yamux driver.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------- trailer

/// `[JSON][u32 LE len]["ORBITAL1"]` appended to a stock binary at download time.
pub const TRAILER_MAGIC: &[u8; 8] = b"ORBITAL1";

pub fn append_trailer(binary: &[u8], json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(binary.len() + json.len() + 12);
    out.extend_from_slice(binary);
    out.extend_from_slice(json);
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(TRAILER_MAGIC);
    out
}

/// Returns the trailer JSON bytes, or None if the data carries no trailer.
pub fn read_trailer(data: &[u8]) -> Option<&[u8]> {
    let n = data.len();
    if n < 12 || &data[n - 8..] != TRAILER_MAGIC {
        return None;
    }
    let len = u32::from_le_bytes(data[n - 12..n - 8].try_into().ok()?) as usize;
    data.get(n.checked_sub(12 + len)?..n - 12)
}

/// Strips an existing trailer so a re-download doesn't stack trailers.
pub fn strip_trailer(data: &[u8]) -> &[u8] {
    match read_trailer(data) {
        Some(t) => &data[..data.len() - t.len() - 12],
        None => data,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentTrailer {
    pub orch_urls: Vec<String>,
    /// hex sha256 of the orchestrator's internal CA certificate (DER)
    pub ca_fingerprint: String,
    pub join_token: String,
}

// ---------------------------------------------------------------- framing

const MAX_FRAME: usize = 1 << 20;

pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let buf = serde_json::to_vec(msg)?;
    w.write_all(&(buf.len() as u32).to_be_bytes()).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME {
        bail!("frame too large: {len}");
    }
    let mut buf = vec![0; len];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

// ---------------------------------------------------------------- messages

/// First message on a fresh TLS connection from the agent.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Hello {
    /// No client cert yet: trade a join token + CSR for a cert.
    Enroll {
        join_token: String,
        csr_pem: String,
        name: String,
        labels: BTreeMap<String, String>,
        services: BTreeMap<String, u16>,
    },
    /// mTLS connection: start the yamux session.
    Connect { version: String, services: BTreeMap<String, u16> },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HelloReply {
    Enrolled {
        node_id: String,
        cert_pem: String,
        ca_pem: String,
        /// hex ed25519 public key used to verify grant tokens
        grant_key: String,
        /// OpenSSH public key of the Orbital SSH CA (for sshd TrustedUserCAKeys)
        ssh_ca: String,
        /// unix seconds
        not_after: u64,
    },
    Ok,
    Error { msg: String },
}

/// Messages on the agent-opened control stream (both directions).
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Control {
    Heartbeat,
    Replicas { urls: Vec<String> },
    Renew { csr_pem: String },
    Renewed { cert_pem: String, not_after: u64 },
}

/// First message on an orchestrator-opened data stream.
#[derive(Serialize, Deserialize, Debug)]
pub struct StreamOpen {
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StreamReply {
    pub ok: bool,
    pub error: Option<String>,
}

// ---------------------------------------------------------------- grant tokens

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GrantClaims {
    pub grant_id: String,
    pub node_id: String,
    pub service: String,
    pub user: String,
    /// unix seconds
    pub exp: u64,
}

pub fn sign_grant(key: &SigningKey, claims: &GrantClaims) -> String {
    let body = B64.encode(serde_json::to_vec(claims).expect("serialize"));
    let sig = key.sign(body.as_bytes());
    format!("{body}.{}", B64.encode(sig.to_bytes()))
}

pub fn verify_grant(key: &VerifyingKey, token: &str, now: u64) -> Result<GrantClaims> {
    let (body, sig) = token.split_once('.').ok_or_else(|| anyhow!("malformed token"))?;
    let sig: [u8; 64] = B64
        .decode(sig)?
        .try_into()
        .map_err(|_| anyhow!("bad signature length"))?;
    key.verify(body.as_bytes(), &Signature::from_bytes(&sig))
        .context("bad grant signature")?;
    let claims: GrantClaims = serde_json::from_slice(&B64.decode(body)?)?;
    if claims.exp < now {
        bail!("grant token expired");
    }
    Ok(claims)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

// ---------------------------------------------------------------- yamux

pub mod mux {
    use futures::future::poll_fn;
    use std::task::Poll;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

    pub use yamux::Mode;
    pub type Stream = Compat<yamux::Stream>;
    type Req = oneshot::Sender<yamux::Result<yamux::Stream>>;

    /// Cheap cloneable handle for opening outbound streams.
    #[derive(Clone)]
    pub struct Mux {
        tx: mpsc::Sender<Req>,
    }

    impl Mux {
        pub async fn open(&self) -> anyhow::Result<Stream> {
            let (tx, rx) = oneshot::channel();
            self.tx.send(tx).await.map_err(|_| anyhow::anyhow!("tunnel closed"))?;
            Ok(rx.await??.compat())
        }
        pub fn is_closed(&self) -> bool {
            self.tx.is_closed()
        }
    }

    /// Spawns the connection driver. The inbound receiver yields `None` once the connection dies.
    pub fn spawn<T>(io: T, mode: Mode) -> (Mux, mpsc::UnboundedReceiver<Stream>)
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mut conn = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);
        let (tx, mut req_rx) = mpsc::channel::<Req>(16);
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut pending: Option<Req> = None;
            poll_fn(|cx| loop {
                let mut progress = false;
                if pending.is_none() {
                    match req_rx.poll_recv(cx) {
                        Poll::Ready(Some(r)) => {
                            pending = Some(r);
                            progress = true;
                        }
                        // every handle dropped: we're done
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                if pending.is_some() {
                    if let Poll::Ready(res) = conn.poll_new_outbound(cx) {
                        let _ = pending.take().unwrap().send(res);
                        progress = true;
                    }
                }
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(s))) => {
                        let _ = in_tx.send(s.compat());
                        progress = true;
                    }
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
                if !progress {
                    return Poll::Pending;
                }
            })
            .await;
            req_rx.close();
        });
        (Mux { tx }, in_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_round_trip() {
        let bin = b"\x7fELF fake binary".to_vec();
        let t = AgentTrailer {
            orch_urls: vec!["orch:8444".into()],
            ca_fingerprint: "ab".repeat(32),
            join_token: "tok".into(),
        };
        let json = serde_json::to_vec(&t).unwrap();
        let out = append_trailer(&bin, &json);
        let got: AgentTrailer = serde_json::from_slice(read_trailer(&out).unwrap()).unwrap();
        assert_eq!(got, t);
        assert_eq!(strip_trailer(&out), &bin[..]);
        assert!(read_trailer(&bin).is_none());
        // re-trailering a trailered binary replaces, not stacks
        let again = append_trailer(strip_trailer(&out), b"{}");
        assert_eq!(read_trailer(&again).unwrap(), b"{}");
        assert_eq!(strip_trailer(&again), &bin[..]);
    }

    #[test]
    fn grant_token_sign_verify() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let c = GrantClaims {
            grant_id: "g".into(),
            node_id: "n".into(),
            service: "ssh".into(),
            user: "alice".into(),
            exp: 1000,
        };
        let tok = sign_grant(&key, &c);
        assert_eq!(verify_grant(&key.verifying_key(), &tok, 999).unwrap(), c);
        assert!(verify_grant(&key.verifying_key(), &tok, 1001).is_err(), "expired");
        let other = SigningKey::from_bytes(&[8; 32]);
        assert!(verify_grant(&other.verifying_key(), &tok, 999).is_err(), "forged");
        let (body, sig) = tok.split_once('.').unwrap();
        let tampered = format!("{}x.{sig}", body);
        assert!(verify_grant(&key.verifying_key(), &tampered, 999).is_err());
    }

    #[tokio::test]
    async fn mux_round_trip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, _cin) = mux::spawn(a, mux::Mode::Client);
        let (_server, mut sin) = mux::spawn(b, mux::Mode::Server);
        let mut s = client.open().await.unwrap();
        write_msg(&mut s, &Control::Heartbeat).await.unwrap();
        let mut r = sin.recv().await.unwrap();
        let m: Control = read_msg(&mut r).await.unwrap();
        assert!(matches!(m, Control::Heartbeat));
    }
}
