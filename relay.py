#!/usr/bin/env python3
"""relay.py -- minimal agent-to-agent message relay. Python stdlib only.

Endpoints (JSON, Bearer auth except /healthz):
  POST /v1/send   {"to","type","payload","ttl_hours"?} -> {"ok","id","ts"}
  GET  /v1/inbox?since=<msg-id>                      -> {"ok","messages":[...]}
  POST /v1/ack    {"ids":[...]}                       -> {"ok","deleted":n}
  GET  /healthz                                       -> {"ok":true}

Notes:
  * "to" is "agent-a", "agent-b" or "broadcast". The reader's identity comes
    from its Bearer token, never from a query parameter.
  * "payload" is opaque to the server (E2EE ciphertext, base64). The server
    never sees plaintext.
  * Messages expire (default 7 days, min 1h, max 30d) and are pruned hourly.
  * Server logs metadata only (no payload, no tokens).
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

CONF_DIR = os.environ.get("RELAY_CONF", "/etc/relay")
DATA_DIR = os.environ.get("RELAY_DATA", "/var/lib/relay")
TOKENS_PATH = os.path.join(CONF_DIR, "tokens.json")  # {sha256_hex(token): agent_id}
STORE_PATH = os.path.join(DATA_DIR, "messages.jsonl")
MAX_BODY = 256 * 1024
DEFAULT_TTL = 7 * 24 * 3600
MIN_TTL = 3600
MAX_TTL = 30 * 24 * 3600
PAGE_SIZE = 200

_lock = threading.Lock()


def load_tokens():
    with open(TOKENS_PATH) as f:
        return json.load(f)


def _iter_messages():
    if not os.path.exists(STORE_PATH):
        return
    with open(STORE_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield line, json.loads(line)
            except ValueError:
                continue


def prune(now=None):
    """Drop expired messages. Returns number dropped."""
    now = now or time.time()
    kept, dropped = [], 0
    for line, m in _iter_messages():
        if isinstance(m, dict) and m.get("exp", 0) > now:
            kept.append(line)
        else:
            dropped += 1
    if dropped:
        tmp = STORE_PATH + ".tmp"
        with open(tmp, "w") as f:
            if kept:
                f.write("\n".join(kept) + "\n")
        os.replace(tmp, STORE_PATH)
    return dropped


def append_message(msg):
    with _lock:
        prune()
        with open(STORE_PATH, "a") as f:
            f.write(json.dumps(msg, separators=(",", ":")) + "\n")


def read_inbox(agent_id, since):
    with _lock:
        prune()
        out = []
        for _, m in _iter_messages():
            if not isinstance(m, dict):
                continue
            if m.get("id", "") <= since:
                continue
            if m.get("to") in (agent_id, "broadcast"):
                out.append(m)
                if len(out) >= PAGE_SIZE:
                    break
        return out


def ack_ids(ids):
    ids = set(ids)
    with _lock:
        kept, dropped = [], 0
        for line, m in _iter_messages():
            if isinstance(m, dict) and m.get("id") in ids:
                dropped += 1
            else:
                kept.append(line)
        tmp = STORE_PATH + ".tmp"
        with open(tmp, "w") as f:
            if kept:
                f.write("\n".join(kept) + "\n")
        os.replace(tmp, STORE_PATH)
        return dropped


class Handler(BaseHTTPRequestHandler):
    server_version = "relay/1.0"

    def log_message(self, fmt, *args):  # metadata-only; stay silent
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth) < 12:
            return None
        digest = hashlib.sha256(auth[7:].strip().encode()).hexdigest()
        agent = None
        for k, v in load_tokens().items():
            if hmac.compare_digest(k, digest):
                agent = v
                break
        return agent

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            return None, "too_large"
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode() or "{}"), None
        except ValueError:
            return None, "bad_json"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, {"ok": True, "ts": int(time.time())})
        if parsed.path == "/v1/inbox":
            agent = self._auth()
            if not agent:
                return self._send(401, {"ok": False, "error": "unauthorized"})
            qs = parse_qs(parsed.query)
            since = qs.get("since", [""])[0]
            if not isinstance(since, str):
                since = ""
            msgs = read_inbox(agent, since)
            return self._send(200, {"ok": True, "messages": msgs})
        return self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/v1/send":
            agent = self._auth()
            if not agent:
                return self._send(401, {"ok": False, "error": "unauthorized"})
            req, err = self._read_json()
            if err:
                return self._send(400 if err != "too_large" else 413,
                                  {"ok": False, "error": err})
            to = req.get("to")
            typ = req.get("type", "note")
            payload = req.get("payload", "")
            if not isinstance(to, str) or not to:
                return self._send(400, {"ok": False, "error": "bad_to"})
            if not isinstance(payload, str) or not payload:
                return self._send(400, {"ok": False, "error": "bad_payload"})
            try:
                ttl = int(req.get("ttl_hours", DEFAULT_TTL // 3600)) * 3600
            except (TypeError, ValueError):
                ttl = DEFAULT_TTL
            ttl = max(MIN_TTL, min(ttl, MAX_TTL))
            now = time.time()
            msg = {
                "id": "%013d-%s" % (int(now * 1000), secrets.token_hex(3)),
                "from": agent,
                "to": to,
                "type": str(typ)[:32],
                "payload": payload,
                "ts": int(now),
                "exp": int(now + ttl),
            }
            append_message(msg)
            return self._send(200, {"ok": True, "id": msg["id"], "ts": msg["ts"]})
        if parsed.path == "/v1/ack":
            agent = self._auth()
            if not agent:
                return self._send(401, {"ok": False, "error": "unauthorized"})
            req, err = self._read_json()
            if err:
                return self._send(400 if err != "too_large" else 413,
                                  {"ok": False, "error": err})
            ids = req.get("ids", [])
            if not isinstance(ids, list):
                return self._send(400, {"ok": False, "error": "bad_ids"})
            n = ack_ids([str(i) for i in ids])
            return self._send(200, {"ok": True, "deleted": n})
        return self._send(404, {"ok": False, "error": "not_found"})


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    port = int(os.environ.get("RELAY_PORT", "443"))
    cert = os.path.join(CONF_DIR, "cert.pem")
    key = os.path.join(CONF_DIR, "key.pem")
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    tls_on = os.path.exists(cert) and os.path.exists(key)
    if tls_on:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    def janitor():
        while True:
            time.sleep(3600)
            try:
                prune()
            except Exception:
                pass

    threading.Thread(target=janitor, daemon=True).start()
    print("relay listening on 0.0.0.0:%d tls=%s" % (port, tls_on), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
