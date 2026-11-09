#!/usr/bin/env python3
"""Minimal WebSocket client for the E2E, standing in for the portal's browser terminal (stdlib only).

usage: ws.py <path> <cookie-jar>
  WS_SEND    text typed into the terminal (plus a newline) once the first output arrives
  WS_SECS    give up after this many seconds (default 30)
  WS_ORIGIN  Origin header (default the orchestrator's URL)
Binary frames (terminal output) go to stdout, text frames (JSON control messages) to stderr.
Exits when the server closes the socket.
"""
import base64, os, socket, ssl, struct, sys, time

HOST, PORT = "orchestrator", 8443


def session_cookie(jar):
    for line in open(jar):
        f = line.rstrip("\n").split("\t")
        if len(f) == 7 and f[5] == "orbital_session":
            return f[6]
    sys.exit("no orbital_session cookie in " + jar)


def frame(op, data):
    # client frames must be masked
    mask, n = os.urandom(4), len(data)
    head = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n))
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def main():
    path, jar = sys.argv[1], sys.argv[2]
    send = os.environ.get("WS_SEND")
    deadline = time.time() + float(os.environ.get("WS_SECS", "30"))
    origin = os.environ.get("WS_ORIGIN", f"https://{HOST}:{PORT}")
    ctx = ssl.create_default_context(cafile="/ca.pem")
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT)), server_hostname=HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origin}\r\n"
               f"Cookie: orbital_session={session_cookie(jar)}\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            sys.exit("connection closed during handshake")
        buf += chunk
    head, buf = buf.split(b"\r\n\r\n", 1)
    if b" 101 " not in head.split(b"\r\n")[0]:
        sys.stderr.write(head.decode(errors="replace") + "\n" + buf.decode(errors="replace") + "\n")
        sys.exit(2)
    s.settimeout(0.5)
    while time.time() < deadline:
        while len(buf) >= 2:
            op, n, off = buf[0] & 0x0F, buf[1] & 0x7F, 2
            if n == 126:
                if len(buf) < 4:
                    break
                n, off = struct.unpack("!H", buf[2:4])[0], 4
            elif n == 127:
                if len(buf) < 10:
                    break
                n, off = struct.unpack("!Q", buf[2:10])[0], 10
            if len(buf) < off + n:
                break
            data, buf = buf[off:off + n], buf[off + n:]
            if op == 2:
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
                if send:
                    s.sendall(frame(2, (send + "\n").encode()))
                    send = None
            elif op == 1:
                sys.stderr.write(data.decode() + "\n")
                sys.stderr.flush()
            elif op == 8:
                return
            elif op == 9:
                s.sendall(frame(10, data))
        try:
            chunk = s.recv(65536)
        except (socket.timeout, TimeoutError):
            continue
        if not chunk:
            return
        buf += chunk


main()
