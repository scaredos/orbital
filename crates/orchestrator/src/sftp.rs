//! Passive SFTP (v3) parser fed with both directions of a relayed `sftp` subsystem channel.
//! Emits one file op per close/remove/rename/mkdir/rmdir/opendir: (op, path, path2, bytes).

use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone)]
pub struct FileOp {
    pub op: &'static str,
    pub path: String,
    pub path2: Option<String>,
    pub bytes: u64,
}

#[derive(Default)]
struct Open {
    path: String,
    read: u64,
    written: u64,
    dir: bool,
}

#[derive(Default)]
pub struct SftpAudit {
    c2s: Vec<u8>,
    s2c: Vec<u8>,
    /// request id -> (path, is_dir) awaiting a HANDLE reply
    pending_open: HashMap<u32, (String, bool)>,
    /// request id -> handle awaiting a DATA reply
    pending_read: HashMap<u32, Vec<u8>>,
    handles: HashMap<Vec<u8>, Open>,
    ops: Vec<FileOp>,
}

struct Rd<'a>(&'a [u8]);
impl Rd<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?);
        self.0 = &self.0[4..];
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        let v = u64::from_be_bytes(self.0.get(..8)?.try_into().ok()?);
        self.0 = &self.0[8..];
        Some(v)
    }
    fn bytes(&mut self) -> Option<&[u8]> {
        let n = self.u32()? as usize;
        let v = self.0.get(..n)?;
        let (v, rest) = (v, &self.0[n..]);
        self.0 = rest;
        Some(v)
    }
    fn string(&mut self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

/// Pops complete `[u32 len][payload]` packets off a buffer.
fn packets(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = vec![];
    loop {
        if buf.len() < 4 {
            break;
        }
        let n = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if n > 1 << 20 {
            buf.clear(); // not SFTP or desynced; stop auditing rather than buffer forever
            break;
        }
        if buf.len() < 4 + n {
            break;
        }
        out.push(buf[4..4 + n].to_vec());
        buf.drain(..4 + n);
    }
    out
}

impl SftpAudit {
    pub fn client(&mut self, data: &[u8]) {
        self.c2s.extend_from_slice(data);
        for p in packets(&mut self.c2s) {
            self.on_client(&p);
        }
    }

    pub fn server(&mut self, data: &[u8]) {
        self.s2c.extend_from_slice(data);
        for p in packets(&mut self.s2c) {
            self.on_server(&p);
        }
    }

    pub fn drain(&mut self) -> Vec<FileOp> {
        std::mem::take(&mut self.ops)
    }

    fn on_client(&mut self, p: &[u8]) -> Option<()> {
        let (&ty, rest) = p.split_first()?;
        let mut r = Rd(rest);
        let op = |op, path, path2| FileOp { op, path, path2, bytes: 0 };
        match ty {
            3 | 11 => {
                // OPEN / OPENDIR
                let id = r.u32()?;
                self.pending_open.insert(id, (r.string()?, ty == 11));
            }
            4 => {
                // CLOSE
                r.u32()?;
                let h = r.bytes()?.to_vec();
                if let Some(o) = self.handles.remove(&h) {
                    let (name, bytes) = match (o.dir, o.written, o.read) {
                        (true, ..) => ("list", 0),
                        (_, w, _) if w > 0 => ("write", w),
                        (_, _, rd) if rd > 0 => ("read", rd),
                        _ => ("open", 0),
                    };
                    self.ops.push(FileOp { op: name, path: o.path, path2: None, bytes });
                }
            }
            5 => {
                // READ
                let id = r.u32()?;
                let h = r.bytes()?.to_vec();
                self.pending_read.insert(id, h);
            }
            6 => {
                // WRITE
                r.u32()?;
                let h = r.bytes()?.to_vec();
                r.u64()?;
                let n = r.bytes()?.len() as u64;
                if let Some(o) = self.handles.get_mut(&h) {
                    o.written += n;
                }
            }
            13 => {
                r.u32()?;
                self.ops.push(op("remove", r.string()?, None));
            }
            14 => {
                r.u32()?;
                self.ops.push(op("mkdir", r.string()?, None));
            }
            15 => {
                r.u32()?;
                self.ops.push(op("rmdir", r.string()?, None));
            }
            18 => {
                r.u32()?;
                let from = r.string()?;
                self.ops.push(op("rename", from, Some(r.string()?)));
            }
            _ => {}
        }
        Some(())
    }

    fn on_server(&mut self, p: &[u8]) -> Option<()> {
        let (&ty, rest) = p.split_first()?;
        let mut r = Rd(rest);
        match ty {
            102 => {
                // HANDLE
                let id = r.u32()?;
                let h = r.bytes()?.to_vec();
                if let Some((path, dir)) = self.pending_open.remove(&id) {
                    self.handles.insert(h, Open { path, dir, ..Default::default() });
                }
            }
            103 => {
                // DATA
                let id = r.u32()?;
                let n = r.bytes()?.len() as u64;
                if let Some(h) = self.pending_read.remove(&id) {
                    if let Some(o) = self.handles.get_mut(&h) {
                        o.read += n;
                    }
                }
            }
            101 => {
                // STATUS: a failed open/read just drops the pending entry
                let id = r.u32()?;
                self.pending_open.remove(&id);
                self.pending_read.remove(&id);
            }
            _ => {}
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(ty: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![ty];
        for f in fields {
            body.extend_from_slice(f);
        }
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend(body);
        out
    }
    fn s(v: &[u8]) -> Vec<u8> {
        let mut o = (v.len() as u32).to_be_bytes().to_vec();
        o.extend_from_slice(v);
        o
    }
    fn u(v: u32) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    #[test]
    fn upload_download_and_misc() {
        let mut a = SftpAudit::default();
        // upload: OPEN, HANDLE, WRITE x2 split across chunks, CLOSE
        let open = pkt(3, &[&u(1), &s(b"/tmp/up.txt"), &u(0x1a), &u(0)]);
        a.client(&open[..5]);
        a.client(&open[5..]);
        a.server(&pkt(102, &[&u(1), &s(b"H1")]));
        a.client(&pkt(6, &[&u(2), &s(b"H1"), &0u64.to_be_bytes(), &s(&[0; 100])]));
        a.client(&pkt(6, &[&u(3), &s(b"H1"), &100u64.to_be_bytes(), &s(&[0; 23])]));
        a.client(&pkt(4, &[&u(4), &s(b"H1")]));
        // download
        a.client(&pkt(3, &[&u(5), &s(b"/etc/hostname"), &u(1), &u(0)]));
        a.server(&pkt(102, &[&u(5), &s(b"H2")]));
        a.client(&pkt(5, &[&u(6), &s(b"H2"), &0u64.to_be_bytes(), &u(32768)]));
        a.server(&pkt(103, &[&u(6), &s(b"myhost\n")]));
        a.client(&pkt(4, &[&u(7), &s(b"H2")]));
        a.client(&pkt(18, &[&u(8), &s(b"/a"), &s(b"/b")]));
        a.client(&pkt(13, &[&u(9), &s(b"/b")]));
        let ops = a.drain();
        assert_eq!(
            ops,
            vec![
                FileOp { op: "write", path: "/tmp/up.txt".into(), path2: None, bytes: 123 },
                FileOp { op: "read", path: "/etc/hostname".into(), path2: None, bytes: 7 },
                FileOp { op: "rename", path: "/a".into(), path2: Some("/b".into()), bytes: 0 },
                FileOp { op: "remove", path: "/b".into(), path2: None, bytes: 0 },
            ]
        );
    }
}
