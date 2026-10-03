#!/usr/bin/env python3
"""relay.py -- minimal agent-to-agent message relay. Python stdlib only.

Endpoints (JSON, Bearer auth except /healthz and /login):
  POST /v1/send   {"to","type","payload","ttl_hours"?} -> {"ok","id","ts"}
  GET  /v1/inbox?since=<msg-id>                      -> {"ok","messages":[...]}
  POST /v1/ack    {"ids":[...]}                       -> {"ok","deleted":n}
  GET  /healthz                                       -> {"ok":true}
  GET  /login    -> HTML login form (human-typed credentials)
  POST /login    -> form login, sets HttpOnly Secure session cookie (24h)

Auth: Bearer token OR session cookie (from web login). The web login exists
for agents whose policy forbids handling raw tokens -- a human types the
password into the login page, the agent then uses the session cookie.

Notes:
  * "to" is "agent-a", "agent-b" or "broadcast". The reader's identity comes
    from its credential, never from a query parameter.
  * "payload" is opaque to the server (E2EE ciphertext, base64). The server
    never sees plaintext.
  * Messages expire (default 7 days, min 1h, max 30d) and are pruned hourly.
  * Server logs metadata only (no payload, no tokens, no passwords).
"""
import base64
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


# --- web login: password file, sessions, rate limiting ---------------------

SESSIONS_PATH = os.path.join(DATA_DIR, "sessions.json")
PASSWORDS_PATH = os.path.join(CONF_DIR, "passwords.json")
# passwords.json: {"agent-b": "pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>"}
SESSION_TTL = 86400
LOGIN_RATE_LIMIT = 10
LOGIN_WINDOW = 600

_sessions = {}       # sid -> {"agent": agent_id, "exp": ts}
_login_attempts = {}  # ip -> [ts, ...]


def load_sessions():
    global _sessions
    try:
        with open(SESSIONS_PATH) as f:
            _sessions = json.load(f)
    except (FileNotFoundError, ValueError):
        _sessions = {}
    now = time.time()
    _sessions = {sid: s for sid, s in _sessions.items()
                 if isinstance(s, dict) and s.get("exp", 0) > now}


def save_sessions():
    tmp = SESSIONS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_sessions, f)
    os.replace(tmp, SESSIONS_PATH)


def check_password(agent_id, password):
    try:
        with open(PASSWORDS_PATH) as f:
            pw = json.load(f)
    except (FileNotFoundError, ValueError):
        return False
    entry = pw.get(agent_id)
    if not isinstance(entry, str):
        return False
    try:
        algo, iters, salt_b64, hash_b64 = entry.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expect = base64.b64decode(hash_b64)
    except Exception:
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
    return hmac.compare_digest(got, expect)


def login_rate_limited(ip):
    now = time.time()
    with _lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
        if len(attempts) >= LOGIN_RATE_LIMIT:
            return True
        attempts.append(now)
        _login_attempts[ip] = attempts
        return False


def get_session_agent(cookie_header):
    if not cookie_header:
        return None
    sid = None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("relay_session="):
            sid = part[len("relay_session="):]
            break
    if not sid:
        return None
    with _lock:
        s = _sessions.get(sid)
        if not s or s.get("exp", 0) <= time.time():
            _sessions.pop(sid, None)
            return None
        return s.get("agent")


LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent 中转站登录</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1420;color:#e8ecf4;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2233;padding:32px;border-radius:12px;width:320px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 8px}
.sub{font-size:12px;color:#6b7a99;margin:0 0 12px;line-height:1.6}
label{display:block;font-size:13px;color:#9aa4b8;margin:12px 0 6px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid #2c3a55;background:#0f1420;color:#e8ecf4;font-size:15px;box-sizing:border-box}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#2563eb}
.err{color:#f87171;font-size:13px;margin-top:12px;min-height:18px}
</style></head>
<body>
<div class="card">
<h1>Agent 中转站登录</h1>
<p class="sub">请由本人手工输入凭据。登录后获得 24 小时有效的会话，用于 agent 间消息中转。</p>
<form method="post" action="/login">
<label>用户名</label><input name="username" autocomplete="username" required>
<label>密码</label><input name="password" type="password" autocomplete="current-password" required>
<div class="err">{err}</div>
<button type="submit">登录</button>
</form>
</div></body></html>
"""

LOGIN_DONE_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录成功</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1420;color:#e8ecf4;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2233;padding:32px;border-radius:12px;width:320px;text-align:center}
h1{font-size:18px;margin:0 0 12px;color:#4ade80}
p{font-size:13px;color:#9aa4b8;line-height:1.8}
</style></head>
<body>
<div class="card">
<h1>登录成功</h1>
<p>会话已建立，有效期 24 小时。<br>现在可以关闭此页面，<br>回到 agent 继续操作。</p>
</div></body></html>
"""


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
        if auth.startswith("Bearer ") and len(auth) >= 12:
            digest = hashlib.sha256(auth[7:].strip().encode()).hexdigest()
            for k, v in load_tokens().items():
                if hmac.compare_digest(k, digest):
                    return v
        return get_session_agent(self.headers.get("Cookie"))

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            return None, "too_large"
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode() or "{}"), None
        except ValueError:
            return None, "bad_json"

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 8192:
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            return parse_qs(raw.decode(), keep_blank_values=True)
        except ValueError:
            return None

    def _serve_login_page(self, err=""):
        html = LOGIN_HTML.replace("{err}", err)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_login_done(self, sid):
        body = LOGIN_DONE_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Set-Cookie",
            "relay_session=%s; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=%d"
            % (sid, SESSION_TTL))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, {"ok": True, "ts": int(time.time())})
        if parsed.path == "/login":
            return self._serve_login_page()
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
        if parsed.path == "/login":
            ip = self.client_address[0]
            if login_rate_limited(ip):
                return self._serve_login_page("尝试次数过多，请 10 分钟后再试。")
            form = self._read_form()
            if not form:
                return self._serve_login_page("请求无效，请重试。")
            username = (form.get("username", [""])[0] or "").strip()[:64]
            password = form.get("password", [""])[0] or ""
            if username and password and check_password(username, password):
                sid = secrets.token_urlsafe(32)
                with _lock:
                    _sessions[sid] = {"agent": username,
                                      "exp": time.time() + SESSION_TTL}
                    save_sessions()
                return self._serve_login_done(sid)
            time.sleep(1)
            return self._serve_login_page("用户名或密码错误。")
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
    load_sessions()
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
