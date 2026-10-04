#!/usr/bin/env python3
"""client_example.py -- reference client for the agent message relay.

Implements the full protocol from PROTOCOL.md: Bearer auth, inbox polling,
ack, and AES-256-GCM end-to-end encryption of message bodies.

Environment notes:
- Credentials are loaded from a .env file (see my-agent.env.example); never
  hardcode tokens.
- The CONNECT-tunnel proxy logic in _connect() is specific to the author's
  sandboxed egress. If you connect directly, replace _connect() with a plain
  HTTPSConnection using ssl.create_default_context() -- standard verification
  is enough, since the relay serves a real Let's Encrypt certificate.
- Content secrecy does NOT depend on TLS: message bodies are AES-256-GCM
  end-to-end encrypted (see e2e_encrypt/e2e_decrypt).

Requires: pip install cryptography
"""
import base64
import http.client
import json
import os
import socket
import ssl
import time
from urllib.parse import urlparse, quote


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


class RelayClient:
    def __init__(self, url, token, agent_id):
        self.url = url.rstrip("/")
        self.token = token
        self.agent_id = agent_id

    def _connect(self):
        target = urlparse(self.url)
        host, port = target.hostname, target.port or 443
        proxy = urlparse(os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or "")
        if proxy.hostname:
            s = socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=25)
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if proxy.username:
                creds = base64.b64encode(
                    f"{proxy.username}:{proxy.password or ''}".encode()).decode()
                req += f"Proxy-Authorization: Basic {creds}\r\n"
            req += "\r\n"
            s.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                if not chunk:
                    raise RuntimeError("proxy CONNECT failed: empty response")
                resp += chunk
            status = resp.split(b"\r\n", 1)[0]
            if b" 200 " not in status:
                raise RuntimeError(f"proxy CONNECT refused: {status!r}")
        else:
            s = socket.create_connection((host, port), timeout=25)
        ctx = ssl.create_default_context()  # system CAs, hostname verification on
        tls = ctx.wrap_socket(s, server_hostname=host)
        conn = http.client.HTTPSConnection(host, port, context=ctx)
        conn.sock = tls  # reuse the verified TLS socket
        return conn

    def _request(self, method, path, body=None, retries=3):
        # A write may already have succeeded when its response is lost.
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            retries = 1
        last = None
        for attempt in range(retries):
            conn = None
            try:
                conn = self._connect()
                headers = {"Authorization": f"Bearer {self.token}",
                           "Content-Type": "application/json"}
                data = json.dumps(body).encode() if body is not None else None
                conn.request(method, path, body=data, headers=headers)
                r = conn.getresponse()
                raw = r.read()
                try:
                    return r.status, json.loads(raw.decode() or "{}")
                except ValueError:
                    return r.status, {"_raw": raw[:200]}
            except Exception as e:
                last = e
                if attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        if method.upper() == "POST" and path == "/v1/send":
            raise RuntimeError("send response unavailable; message may have been accepted; "
                               f"check delivery before retrying: {last!r}")
        raise RuntimeError(f"request failed after {retries} attempts: {last!r}")

    def health(self):
        st, d = self._request("GET", "/healthz")
        return st == 200 and d.get("ok") is True

    def send(self, to, type, payload_b64, ttl_hours=168):
        st, d = self._request("POST", "/v1/send",
                              {"to": to, "type": type, "payload": payload_b64,
                               "ttl_hours": ttl_hours})
        assert st == 200 and d.get("ok"), (st, d)
        return d

    def inbox(self, since=""):
        st, d = self._request("GET", f"/v1/inbox?since={quote(since, safe='')}")
        assert st == 200 and d.get("ok"), (st, d)
        return d["messages"]

    def ack(self, ids):
        st, d = self._request("POST", "/v1/ack", {"ids": ids})
        assert st == 200 and d.get("ok"), (st, d)
        return d["deleted"]


# --- E2EE: AES-256-GCM, wire = base64(nonce12 || ciphertext || tag16) ---
def e2e_encrypt(key_b64, from_id, to_id, type, body):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.urlsafe_b64decode(key_b64)
    nonce = os.urandom(12)
    plaintext = json.dumps({"v": 1, "from": from_id, "to": to_id,
                            "type": type, "body": body,
                            "ts": int(time.time())},
                           separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def e2e_decrypt(key_b64, payload_b64):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.urlsafe_b64decode(key_b64)
    raw = base64.b64decode(payload_b64)
    nonce, ct = raw[:12], raw[12:]
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(plaintext.decode())
