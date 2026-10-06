#!/usr/bin/env python3
"""relay.py -- minimal agent-to-agent message relay. Python stdlib only.

Endpoints (JSON, Bearer auth except /healthz and /login):
  POST /v1/send   {"to","type","payload","ttl_hours"?} -> {"ok","id","ts"}
  GET  /v1/inbox?since=<msg-id>                      -> {"ok","messages":[...]}
  POST /v1/ack    {"ids":[...]}                       -> {"ok","deleted":n}
  GET  /healthz                                       -> {"ok":true}
  GET  /login    -> HTML login form (human-typed credentials)
  POST /login    -> form login, sets HttpOnly Secure session cookie (24h)
  GET  /app      -> web message desk (session required)
  POST /logout   -> destroy session

OAuth 2.0 Device Authorization Grant (RFC 8628) for CLI/SDK auth:
  POST /oauth/device/code -> {device_code, user_code, verification_uri, ...}
  GET  /oauth/device      -> user enters code + consent page (login required)
  POST /oauth/token       -> device_code / refresh_token grants
  POST /oauth/revoke      -> revoke an access/refresh token

Auth: Bearer token (static or OAuth access) OR session cookie.

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
import html
import re
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

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
    with _lock:
        return _prune_unlocked(now)


def _prune_unlocked(now=None):
    """Caller must hold _lock, including the background janitor."""
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
        _prune_unlocked()
        with open(STORE_PATH, "a") as f:
            f.write(json.dumps(msg, separators=(",", ":")) + "\n")


def read_inbox(agent_id, since):
    with _lock:
        _prune_unlocked()
        out = []
        for _, m in _iter_messages():
            if not isinstance(m, dict):
                continue
            if m.get("id", "") <= since:
                continue
            if m.get("to") in (agent_id, "broadcast"):
                if agent_id in m.get("_acked_by", []):
                    continue
                out.append({k: v for k, v in m.items() if k != "_acked_by"})
                if len(out) >= PAGE_SIZE:
                    break
        return out


def ack_ids(agent_id, ids):
    """Acknowledge only this recipient's delivery; broadcast stays until TTL."""
    ids = set(ids)
    with _lock:
        kept, dropped = [], 0
        for line, m in _iter_messages():
            if isinstance(m, dict) and m.get("id") in ids:
                if m.get("to") == agent_id:
                    dropped += 1
                    continue
                if m.get("to") == "broadcast":
                    acked = m.setdefault("_acked_by", [])
                    if agent_id not in acked:
                        acked.append(agent_id)
                        dropped += 1
                        line = json.dumps(m, separators=(",", ":"))
            kept.append(line)
        tmp = STORE_PATH + ".tmp"
        with open(tmp, "w") as f:
            if kept:
                f.write("\n".join(kept) + "\n")
        os.replace(tmp, STORE_PATH)
        return dropped


# --- OAuth 2.0 Device Authorization Grant (RFC 8628) ---------------------------
# Lets a CLI/SDK obtain a Bearer token without ever handling the user's
# password: the CLI shows a user_code, the human authorizes it on the
# /oauth/device web page (logged in via /login), the CLI polls /oauth/token.

OAUTH_STORE = os.path.join(DATA_DIR, "oauth.json")
OAUTH_CLIENTS = {"relay-cli": "relay CLI"}
DEVICE_CODE_TTL = 600
DEVICE_POLL_INTERVAL = 5
ACCESS_TOKEN_TTL = 30 * 86400
REFRESH_TOKEN_TTL = 90 * 86400
KEY_HANDOFF_ALG = "RSA-OAEP-256"
KEY_HANDOFF_BYTES = 384  # RSA-3072; only the 32-byte E2EE key is encrypted.
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789"  # no vowels, no 0/1


def validate_handoff_public_key(algorithm, encoded):
    """Accept only a public RSA-3072 JWK, without server crypto dependencies."""
    if algorithm != KEY_HANDOFF_ALG or not isinstance(encoded, str) or len(encoded) > 1024:
        raise ValueError("invalid handoff key")
    key = json.loads(encoded)
    if not isinstance(key, dict) or set(key) != {"kty", "alg", "n", "e"}:
        raise ValueError("invalid handoff key")
    if key["kty"] != "RSA" or key["alg"] != KEY_HANDOFF_ALG or key["e"] != "AQAB":
        raise ValueError("invalid handoff key")
    n = key["n"]
    if not isinstance(n, str) or not re.fullmatch(r"[A-Za-z0-9_-]{512}", n):
        raise ValueError("invalid handoff key")
    modulus = base64.b64decode(n, altchars=b"-_", validate=True)
    if len(modulus) != KEY_HANDOFF_BYTES or modulus[0] < 128 or not modulus[-1] & 1:
        raise ValueError("invalid handoff key")
    return key


def valid_handoff_ciphertext(value):
    if not isinstance(value, str) or len(value) != 512:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == KEY_HANDOFF_BYTES and base64.b64encode(raw).decode() == value
    except ValueError:
        return False


def consent_token(session, device_code, client_id):
    """Caller holds _lock. Bind approval to a session, request and identity."""
    if "consent_secret" not in session:
        session["consent_secret"] = secrets.token_urlsafe(32)
        save_sessions()
    context = json.dumps(["relay-device-consent-v1", device_code, client_id,
                          session["agent"]], separators=(",", ":")).encode()
    return hmac.new(session["consent_secret"].encode(), context, hashlib.sha256).hexdigest()


def load_oauth():
    try:
        with open(OAUTH_STORE) as f:
            d = json.load(f)
    except (FileNotFoundError, ValueError):
        d = {}
    d.setdefault("device", {})
    d.setdefault("access", {})
    d.setdefault("refresh", {})
    return d


def save_oauth(d):
    tmp = OAUTH_STORE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, OAUTH_STORE)


def prune_oauth():
    now = time.time()
    with _lock:
        d = load_oauth()
        d["device"] = {k: v for k, v in d["device"].items()
                       if v.get("exp", 0) > now}
        d["access"] = {k: v for k, v in d["access"].items()
                       if v.get("exp", 0) > now}
        d["refresh"] = {k: v for k, v in d["refresh"].items()
                        if v.get("exp", 0) > now}
        save_oauth(d)


def new_user_code():
    return "-".join("".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(4))
                   for _ in range(2))


def normalize_user_code(s):
    return (s or "").strip().upper().replace(" ", "").replace("-", "")


def valid_next(nxt):
    return isinstance(nxt, str) and nxt.startswith("/") and not nxt.startswith("//")


def public_base(handler):
    override = os.environ.get("RELAY_PUBLIC_BASE")
    if override:
        return override.rstrip("/")
    host = (handler.headers.get("Host") or "").split(":")[0] or "localhost"
    return "https://%s" % host


def bearer_agent(token):
    """Return agent_id for a Bearer token (static tokens or OAuth access)."""
    digest = hashlib.sha256(token.encode()).hexdigest()
    for k, v in load_tokens().items():
        if hmac.compare_digest(k, digest):
            return v
    now = time.time()
    for k, v in load_oauth()["access"].items():
        if hmac.compare_digest(k, digest):
            return v.get("agent") if v.get("exp", 0) > now else None
    return None


def issue_token_pair(agent, client_id, scope):
    with _lock:
        d = load_oauth()
        pair = _issue_token_pair(d, agent, client_id, scope)
        save_oauth(d)
        return pair


def _issue_token_pair(d, agent, client_id, scope):
    """Mutate the OAuth transaction held by the caller under _lock."""
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    now = time.time()
    # Preserve the existing one-active-pair-per-(agent, client) policy.
    for store in ("access", "refresh"):
        d[store] = {k: v for k, v in d[store].items()
                    if not (v.get("agent") == agent and
                            v.get("client_id") == client_id)}
    ah = hashlib.sha256(access.encode()).hexdigest()
    rh = hashlib.sha256(refresh.encode()).hexdigest()
    d["access"][ah] = {"agent": agent, "exp": now + ACCESS_TOKEN_TTL,
                       "client_id": client_id, "scope": scope}
    d["refresh"][rh] = {"agent": agent, "exp": now + REFRESH_TOKEN_TTL,
                        "client_id": client_id, "scope": scope,
                        "access_hash": ah}
    return access, refresh


DEVICE_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>设备授权</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1420;color:#e8ecf4;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2233;padding:32px;border-radius:12px;width:340px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:18px;margin:0 0 8px}
.sub{font-size:12px;color:#6b7a99;margin:0 0 16px;line-height:1.7}
label{display:block;font-size:13px;color:#9aa4b8;margin:12px 0 6px}
input{width:100%;padding:12px;border-radius:8px;border:1px solid #2c3a55;background:#0f1420;color:#e8ecf4;font-size:20px;letter-spacing:4px;text-align:center;box-sizing:border-box;text-transform:uppercase}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#2563eb}
button.deny{background:transparent;border:1px solid #f87171;color:#f87171;margin-top:10px}
.err{color:#f87171;font-size:13px;margin-top:12px;min-height:18px}
.code{font-size:28px;letter-spacing:6px;text-align:center;margin:12px 0;font-weight:700}
.meta{font-size:13px;color:#9aa4b8;line-height:1.8}
</style></head>
<body>
<div class="card">
<h1>设备授权</h1>
{body}
</div></body></html>
"""

DEVICE_ENTRY_BODY = """
<p class="sub">在你的 CLI / SDK 上看到一组 8 位代码？把它输在这里，授权该设备以你的身份访问中转站。</p>
<form method="post" action="/oauth/device/verify">
<label>设备代码</label><input name="user_code" placeholder="XXXX-XXXX" autocomplete="off" required>
<div class="err">{err}</div>
<button type="submit">下一步</button>
</form>
"""

DEVICE_CONSENT_BODY = """
<p class="sub">应用 <b>{client}</b> 请求以你的身份 <b>{agent}</b> 访问 agent 消息中转站（收发加密消息，有效期 30 天）。</p>
<p class="sub">请核对代码与您自己刚发起的 CLI 完全一致；不要授权他人发来的代码。</p>
<p class="meta">设备代码：<span class="code" style="font-size:18px">{user_code}</span></p>
<form id="consent-form" method="post" action="/oauth/device/authorize">
<input type="hidden" name="device_code" value="{device_code}">
<input type="hidden" name="csrf_token" value="{csrf_token}">
{key_handoff}
<div class="err">{err}</div>
<button id="approve-button" type="submit" name="action" value="approve">授权</button>
<button type="submit" class="deny" name="action" value="deny" formnovalidate>拒绝</button>
</form>
"""

# The plaintext input intentionally has NO name: even without JavaScript it
# cannot be included in a native form POST. Only the encrypted envelope is sent.
DEVICE_KEY_HANDOFF = """
<label for="handoff-key">现有 E2EE 密钥</label>
<input id="handoff-key" type="password" autocomplete="off" spellcheck="false"
       style="text-transform:none;letter-spacing:normal" required>
<p class="sub">授权会将此共享密钥加密交给该 CLI，并保存于它的本地配置。请仅向您信任的设备授权。</p>
<input type="hidden" id="key-handoff" name="key_handoff" value="">
<p id="handoff-error" class="err" role="alert"></p>
<noscript>需要启用 JavaScript 和 Web Crypto 才能安全交接密钥；也可拒绝并使用旧的手动配置方式。</noscript>
<script id="handoff-data" type="application/json">{handoff_data}</script>
<script>
async function encryptHandoffKey(value, data) {
  const encoded = value.trim();
  if (!/^[A-Za-z0-9_-]{43}=?$/.test(encoded)) throw new Error('invalid key');
  const bytes = Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  if (bytes.length !== 32) throw new Error('invalid key');
  const publicKey = await crypto.subtle.importKey('jwk', data.public_key,
    {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
  try {
    const ciphertext = await crypto.subtle.encrypt({name: 'RSA-OAEP',
      label: new TextEncoder().encode(JSON.stringify(data.label))}, publicKey, bytes);
    return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  } finally { bytes.fill(0); }
}
document.addEventListener('DOMContentLoaded', () => {
const handoffForm = document.getElementById('consent-form');
const handoffInput = document.getElementById('handoff-key');
const handoffOutput = document.getElementById('key-handoff');
const handoffError = document.getElementById('handoff-error');
const approveButton = document.getElementById('approve-button');
const handoffData = JSON.parse(document.getElementById('handoff-data').textContent);
let handoffBusy = false;
let handoffCancelled = false;
handoffForm.addEventListener('submit', async event => {
  if (event.submitter && event.submitter.value === 'deny') {
    handoffCancelled = true;
    handoffInput.value = '';
    handoffOutput.value = '';
    return;
  }
  event.preventDefault();
  if (handoffBusy || handoffCancelled) return;
  handoffBusy = true;
  approveButton.disabled = true;
  handoffError.textContent = '';
  try {
    if (!window.isSecureContext || !crypto.subtle) throw new Error('Web Crypto unavailable');
    const value = handoffInput.value;
    handoffInput.value = '';
    const ciphertext = await encryptHandoffKey(value, handoffData);
    if (handoffCancelled) return;
    handoffOutput.value = ciphertext;
    // Native submit() omits the submit button, so explicitly preserve approval.
    const action = document.createElement('input');
    action.type = 'hidden'; action.name = 'action'; action.value = 'approve';
    handoffForm.appendChild(action);
    handoffForm.submit();
  } catch (_) {
    handoffOutput.value = '';
    handoffError.textContent = '无法加密密钥。请确认 HTTPS、浏览器支持 Web Crypto，并重新输入 32 字节 base64url 密钥。';
    handoffBusy = false;
    approveButton.disabled = false;
  }
});
window.addEventListener('pagehide', () => { handoffCancelled = true; handoffInput.value = ''; handoffOutput.value = ''; });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
});
</script>
"""

DEVICE_DONE_BODY = """
<p class="sub" style="font-size:15px;color:#4ade80">{msg}</p>
<p class="sub">现在可以关闭此页面，回到你的 CLI 继续操作。</p>
"""

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


def session_id_from_cookie(cookie_header):
    if not cookie_header:
        return None
    sid = None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("relay_session="):
            sid = part[len("relay_session="):]
            break
    return sid


def get_session_agent(cookie_header):
    sid = session_id_from_cookie(cookie_header)
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
{next_input}<label>用户名</label><input name="username" autocomplete="username" required>
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
<p>会话已建立，有效期 24 小时。</p>
<p><a href="/app" style="display:inline-block;margin-top:8px;padding:12px 28px;background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;font-size:15px">前往消息台 →</a></p>
<p style="font-size:12px">在消息台粘贴 E2EE 密钥后，即可收发端到端加密消息。</p>
</div></body></html>
"""

APP_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent 消息台</title>
<style>
:root{--bg:#0f1420;--card:#1a2233;--line:#2c3a55;--txt:#e8ecf4;--dim:#9aa4b8;--acc:#3b82f6;--ok:#4ade80;--err:#f87171}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);margin:0;padding:16px;max-width:640px;margin-left:auto;margin-right:auto}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
header h1{font-size:18px;margin:0}
header .who{font-size:12px;color:var(--dim);margin-top:4px}
.card{background:var(--card);border-radius:12px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;margin:0 0 12px;color:var(--dim);font-weight:600}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
input,select,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--txt);font-size:14px}
textarea{min-height:90px;resize:vertical}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 16px;font-size:14px;cursor:pointer}
button:hover{background:#2563eb}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
button.danger{background:transparent;border:1px solid var(--err);color:var(--err);padding:6px 12px;font-size:12px}
.row{display:flex;gap:8px;align-items:center}
.hint{font-size:12px;color:var(--dim);line-height:1.7;margin-top:8px}
.msg{border:1px solid var(--line);border-radius:8px;padding:10px;margin-bottom:8px}
.msg .meta{font-size:12px;color:var(--dim);margin-bottom:6px}
.msg .body{font-size:14px;white-space:pre-wrap;word-break:break-word}
.msg .foot{margin-top:8px;text-align:right}
.status{font-size:13px;min-height:20px;margin-top:8px}
.status.ok{color:var(--ok)} .status.err{color:var(--err)}
.keyrow{display:flex;gap:8px}
.keyrow input{flex:1}
.keyrow button{flex:0 0 auto}
.badge{display:inline-block;font-size:11px;padding:2px 8px;border-radius:10px;background:#233252;color:var(--dim)}
.badge.on{background:#14331f;color:var(--ok)}
</style>
</head>
<body>
<header>
  <div><h1>Agent 消息台</h1><div class="who">已登录为 <b>{agent}</b> · 会话 24 小时有效</div></div>
  <button class="ghost" id="logoutBtn">退出</button>
</header>

<div class="card">
  <h2>端到端加密密钥 <span class="badge" id="keyBadge">未载入</span></h2>
  <div class="keyrow">
    <input id="e2eKey" type="password" placeholder="粘贴 E2EE 密钥" autocomplete="off">
    <button id="loadKeyBtn">载入</button>
  </div>
  <div class="hint">密钥只保存在本浏览器标签页内，用于在本地加解密消息正文，绝不会发送到服务器。关闭标签页即清除。</div>
</div>

<div class="card">
  <h2>发消息</h2>
  <label>收件人</label>
  <select id="toSel"><option value="agent-a">agent-a</option><option value="agent-b">agent-b</option><option value="broadcast">broadcast（所有人）</option></select>
  <label>类型</label>
  <input id="typeInp" value="note" maxlength="32">
  <label>正文</label>
  <textarea id="bodyInp" placeholder="输入消息正文，将在本地加密后发送"></textarea>
  <div class="row" style="margin-top:10px"><button id="sendBtn">加密并发送</button></div>
  <div class="status" id="sendStatus"></div>
</div>

<div class="card">
  <h2>收件箱 <button class="ghost" id="refreshBtn" style="padding:6px 12px;font-size:12px;margin-left:8px">刷新</button></h2>
  <div id="inbox"><div class="hint">点击刷新载入消息（每 30 秒自动刷新）。</div></div>
</div>

<script>
"use strict";
const AGENT = "{agent}";
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
let cryptoKey = null;

function b64ToBytes(b64url){
  let b64 = b64url.trim().replace(/-/g,'+').replace(/_/g,'/');
  while (b64.length % 4) b64 += '=';
  const s = atob(b64), out = new Uint8Array(s.length);
  for (let i=0;i<s.length;i++) out[i]=s.charCodeAt(i);
  return out;
}
function bytesToB64(bytes){
  let s=''; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
async function importKey(b64url){
  const raw = b64ToBytes(b64url);
  if (raw.length !== 32) throw new Error('密钥长度应为 32 字节，实际 '+raw.length);
  return crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
async function e2eEncrypt(key, to, type, body){
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const pt = enc.encode(JSON.stringify({v:1,from:AGENT,to:to,type:type,body:body,ts:Math.floor(Date.now()/1000)}));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce}, key, pt));
  const wire = new Uint8Array(12+ct.length); wire.set(nonce); wire.set(ct,12);
  return bytesToB64(wire);
}
async function e2eDecrypt(key, payloadB64){
  const wire = b64ToBytes(payloadB64);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:wire.slice(0,12)}, key, wire.slice(12));
  return JSON.parse(dec.decode(pt));
}
async function api(method, path, body){
  const r = await fetch(path, {method:method, credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: body!==undefined ? JSON.stringify(body) : undefined});
  if (r.status===401){ location.href='/login'; throw new Error('会话已失效，请重新登录'); }
  return r.json();
}
function setStatus(el, msg, ok){
  el.textContent = msg;
  el.className = 'status' + (ok===true ? ' ok' : ok===false ? ' err' : '');
}
async function loadKey(){
  const v = $('e2eKey').value;
  try{
    cryptoKey = await importKey(v);
    sessionStorage.setItem('e2e_key', v.trim());
    $('keyBadge').textContent='已载入'; $('keyBadge').classList.add('on');
    refreshInbox();
  }catch(e){ setStatus($('sendStatus'), '密钥无效：'+e.message, false); }
}
async function refreshInbox(){
  const box = $('inbox');
  try{
    const d = await api('GET','/v1/inbox?since=');
    const msgs = d.messages || [];
    if(!msgs.length){ box.innerHTML='<div class="hint">收件箱是空的。</div>'; return; }
    box.innerHTML='';
    for(const m of msgs){
      const div=document.createElement('div'); div.className='msg';
      const t=new Date(m.ts*1000).toLocaleString();
      const meta=document.createElement('div'); meta.className='meta';
      meta.textContent='来自 '+m.from+' · '+m.type+' · '+t;
      div.appendChild(meta);
      const bodyDiv=document.createElement('div'); bodyDiv.className='body';
      if(cryptoKey){
        try{ const p=await e2eDecrypt(cryptoKey, m.payload); bodyDiv.textContent=p.body||'(空正文)'; }
        catch(e){ bodyDiv.innerHTML='<span class="badge">解密失败（密钥不匹配？）</span>'; }
      }else{
        bodyDiv.innerHTML='<span class="badge">载入密钥后解密查看</span>';
      }
      div.appendChild(bodyDiv);
      const foot=document.createElement('div'); foot.className='foot';
      const btn=document.createElement('button'); btn.className='danger'; btn.textContent='确认已读并删除';
      btn.onclick=((mid)=>async()=>{ await api('POST','/v1/ack',{ids:[mid]}); refreshInbox(); })(m.id);
      foot.appendChild(btn); div.appendChild(foot);
      box.appendChild(div);
    }
  }catch(e){ box.innerHTML='<div class="hint">载入失败：'+String(e.message||e)+'</div>'; }
}
async function sendMsg(){
  if(!cryptoKey){ setStatus($('sendStatus'),'请先载入 E2EE 密钥',false); return; }
  const to=$('toSel').value, type=$('typeInp').value.trim()||'note', body=$('bodyInp').value;
  if(!body.trim()){ setStatus($('sendStatus'),'正文不能为空',false); return; }
  setStatus($('sendStatus'),'加密发送中…',null);
  try{
    const payload=await e2eEncrypt(cryptoKey,to,type,body);
    const d=await api('POST','/v1/send',{to:to,type:type,payload:payload});
    if(d.ok){ setStatus($('sendStatus'),'发送成功',true); $('bodyInp').value=''; }
    else setStatus($('sendStatus'),'发送失败：'+(d.error||'未知错误'),false);
  }catch(e){ setStatus($('sendStatus'),'发送失败：'+String(e.message||e),false); }
}
$('loadKeyBtn').onclick=loadKey;
$('e2eKey').addEventListener('keydown',e=>{ if(e.key==='Enter') loadKey(); });
$('sendBtn').onclick=sendMsg;
$('refreshBtn').onclick=refreshInbox;
$('logoutBtn').onclick=async()=>{
  await fetch('/logout',{method:'POST',credentials:'include'});
  sessionStorage.removeItem('e2e_key');
  location.href='/login';
};
(function init(){
  const saved=sessionStorage.getItem('e2e_key');
  if(saved){ $('e2eKey').value=saved; loadKey(); }
  refreshInbox();
  setInterval(refreshInbox, 30000);
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    # Per-connection socket timeout: drops slowloris-style / half-open
    # connections instead of leaking a handler thread forever. The service
    # previously wedged (stopped accept()ing) twice in 12h; combined with the
    # local healthcheck cron (see healthcheck.sh) it now self-heals.
    timeout = 30

    server_version = "relay/1.0"

    def log_message(self, fmt, *args):  # metadata-only; stay silent
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if self.path.startswith("/oauth/"):
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and len(auth) >= 12:
            agent = bearer_agent(auth[7:].strip())
            if agent:
                return agent
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

    def _serve_login_page(self, err="", nxt=""):
        nxt_input = ""
        if nxt:
            nxt_input = '<input type="hidden" name="next" value="%s">' % nxt.replace('"', "")
        html = LOGIN_HTML.replace("{err}", err).replace("{next_input}", nxt_input)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_login_done(self, sid, nxt=""):
        if nxt:
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header(
                "Set-Cookie",
                "relay_session=%s; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=%d"
                % (sid, SESSION_TTL))
            self.end_headers()
            return
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

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()

    def _serve_app(self, agent):
        html = APP_HTML.replace("{agent}", agent)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _logout(self):
        sid = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("relay_session="):
                sid = part[len("relay_session="):]
                break
        if sid:
            with _lock:
                _sessions.pop(sid, None)
                save_sessions()
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "relay_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
        self.end_headers()

    # --- OAuth device flow handlers --------------------------------------

    def _oauth_error(self, status, error, description=""):
        body = {"error": error}
        if description:
            body["error_description"] = description
        return self._send(status, body)

    def _device_page(self, body_html):
        html = DEVICE_HTML.replace("{body}", body_html)
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _read_params(self):
        """Accept JSON or form-encoded bodies, return a flat dict.

        Reads the request body exactly once, then tries JSON first,
        falling back to form parsing on the same bytes.
        """
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 65536:
            return {}
        raw = self.rfile.read(length) if length else b""
        try:
            text = raw.decode()
        except ValueError:
            return {}
        try:
            d = json.loads(text or "{}")
            if isinstance(d, dict):
                return {k: (v[0] if isinstance(v, list) else v)
                        for k, v in d.items()}
        except ValueError:
            pass
        try:
            form = parse_qs(text, keep_blank_values=True)
        except ValueError:
            return {}
        return {k: v[0] for k, v in form.items() if v}

    def _handle_device_code(self):
        ip = self.client_address[0]
        if login_rate_limited(ip):
            return self._oauth_error(429, "slow_down", "too many requests")
        params = self._read_params()
        client_id = params.get("client_id", "")
        if client_id not in OAUTH_CLIENTS:
            return self._oauth_error(400, "invalid_client")
        handoff_key = None
        if "key_handoff_alg" in params or "key_handoff_public_key" in params:
            try:
                handoff_key = validate_handoff_public_key(
                    params.get("key_handoff_alg"), params.get("key_handoff_public_key"))
            except (ValueError, TypeError):
                return self._oauth_error(400, "invalid_request", "invalid key handoff parameters")
        scope = str(params.get("scope", "relay"))[:64] or "relay"
        device_code = secrets.token_urlsafe(32)
        user_code = new_user_code()
        now = time.time()
        with _lock:
            d = load_oauth()
            d["device"][device_code] = {
                "user_code": normalize_user_code(user_code),
                "client_id": client_id, "scope": scope,
                "exp": now + DEVICE_CODE_TTL, "status": "pending",
                "agent": None, "last_poll": 0}
            if handoff_key:
                d["device"][device_code]["key_handoff_public_key"] = handoff_key
            save_oauth(d)
        base = public_base(self)
        return self._send(200, {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": base + "/oauth/device",
            "verification_uri_complete":
                base + "/oauth/device?code=" + quote(user_code, safe=""),
            "expires_in": DEVICE_CODE_TTL,
            "interval": DEVICE_POLL_INTERVAL,
            **({"key_handoff_alg": KEY_HANDOFF_ALG} if handoff_key else {}),
        })

    def _handle_device_page(self, qs):
        cookie = self.headers.get("Cookie")
        agent = get_session_agent(cookie)
        if not agent:
            nxt = "/oauth/device"
            code = (qs.get("code", [""])[0] or "").strip()
            if code:
                nxt += "?code=" + quote(code, safe="")
            return self._redirect("/login?next=" + quote(nxt, safe=""))
        code = normalize_user_code(qs.get("code", [""])[0])
        if code:
            now = time.time()
            with _lock:
                session = _sessions.get(session_id_from_cookie(cookie))
                if not session or session.get("exp", 0) <= now:
                    return self._send(401, {"error": "unauthorized"})
                agent = session["agent"]
                d = load_oauth()
                match = [(dc, v) for dc, v in d["device"].items()
                         if v.get("user_code") == code
                         and v.get("status") == "pending"
                         and v.get("exp", 0) > now]
                if match:
                    dc, v = match[0]
                    csrf = consent_token(session, dc, v["client_id"])
            if not match:
                return self._device_page(
                    DEVICE_ENTRY_BODY.replace("{err}", "代码无效或已过期，请重新输入。"))
            uc = v["user_code"]
            disp = uc[:4] + "-" + uc[4:]
            key_html = ""
            if v.get("key_handoff_public_key"):
                data = {"public_key": v["key_handoff_public_key"],
                        "label": ["relay-e2ee-handoff-v1", dc, v["client_id"], agent]}
                # Escaping '<' prevents a configured identity closing the script.
                encoded = json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
                key_html = DEVICE_KEY_HANDOFF.replace("{handoff_data}", encoded)
            body = DEVICE_CONSENT_BODY.replace(
                "{client}", html.escape(OAUTH_CLIENTS.get(v["client_id"], v["client_id"])))
            body = body.replace("{agent}", html.escape(agent)).replace("{user_code}", html.escape(disp))
            body = body.replace("{device_code}", html.escape(dc, quote=True))
            body = body.replace("{csrf_token}", csrf).replace("{err}", "")
            return self._device_page(body.replace("{key_handoff}", key_html))
        return self._device_page(DEVICE_ENTRY_BODY.replace("{err}", ""))

    def _handle_device_verify(self):
        agent = get_session_agent(self.headers.get("Cookie"))
        if not agent:
            return self._redirect("/login?next=" + quote("/oauth/device", safe=""))
        form = self._read_form() or {}
        code = normalize_user_code((form.get("user_code") or [""])[0])
        return self._redirect("/oauth/device?code=" + quote(code, safe=""))

    def _handle_device_authorize(self):
        sid = session_id_from_cookie(self.headers.get("Cookie"))
        form = self._read_form() or {}
        dc = (form.get("device_code") or [""])[0]
        action = (form.get("action") or [""])[0]
        with _lock:
            session = _sessions.get(sid)
            if not session or session.get("exp", 0) <= time.time():
                return self._send(401, {"error": "unauthorized"})
            agent = session["agent"]
            d = load_oauth()
            v = d["device"].get(dc)
            if not v or v.get("exp", 0) <= time.time():
                d["device"].pop(dc, None)
                save_oauth(d)
                return self._device_page(DEVICE_DONE_BODY.replace(
                    "{msg}", "该授权请求已过期，请让 CLI 重新发起。"))
            csrf = (form.get("csrf_token") or [""])[0]
            if not hmac.compare_digest(csrf.encode(), consent_token(session, dc, v["client_id"]).encode()):
                return self._send(403, {"error": "invalid_consent"})
            if v.get("status") != "pending":
                return self._device_page(DEVICE_DONE_BODY.replace(
                    "{msg}", "该请求已处理过，无需重复操作。"))
            if action not in ("approve", "deny"):
                return self._send(400, {"error": "invalid_request"})
            if action == "approve":
                if v.get("key_handoff_public_key"):
                    ciphertext = (form.get("key_handoff") or [""])[0]
                    if not valid_handoff_ciphertext(ciphertext):
                        return self._send(400, {"error": "invalid_key_handoff"})
                    v["key_handoff"] = {"alg": KEY_HANDOFF_ALG,
                                        "ciphertext": ciphertext, "agent": agent}
                v["status"] = "approved"
                v["agent"] = agent
                msg = "已授权 %s，CLI 将自动获得访问令牌%s。" % (
                    html.escape(OAUTH_CLIENTS.get(v["client_id"], v["client_id"])),
                    "和加密的 E2EE 密钥" if v.get("key_handoff") else "")
            else:
                v["status"] = "denied"
                msg = "已拒绝授权，CLI 不会获得访问令牌或密钥。"
            save_oauth(d)
        return self._device_page(DEVICE_DONE_BODY.replace("{msg}", msg))

    def _handle_token(self):
        params = self._read_params()
        grant = params.get("grant_type", "")
        client_id = params.get("client_id", "")
        if client_id not in OAUTH_CLIENTS:
            return self._oauth_error(400, "invalid_client")
        if grant == "urn:ietf:params:oauth:grant-type:device_code":
            dc = params.get("device_code", "")
            with _lock:
                now = time.time()
                d = load_oauth()
                v = d["device"].get(dc)
                if not v:
                    return self._oauth_error(400, "invalid_grant",
                                             "unknown device code")
                if v.get("client_id") != client_id:
                    return self._oauth_error(400, "invalid_grant")
                if v.get("exp", 0) <= now:
                    del d["device"][dc]
                    save_oauth(d)
                    return self._oauth_error(400, "expired_token")
                if now - v.get("last_poll", 0) < DEVICE_POLL_INTERVAL:
                    return self._oauth_error(400, "slow_down")
                v["last_poll"] = now
                save_oauth(d)
                status = v.get("status")
                if status == "pending":
                    return self._oauth_error(400, "authorization_pending")
                if status == "denied":
                    del d["device"][dc]
                    save_oauth(d)
                    return self._oauth_error(400, "access_denied")
                agent, scope = v["agent"], v.get("scope", "relay")
                del d["device"][dc]
                access, refresh = _issue_token_pair(d, agent, client_id, scope)
                save_oauth(d)
            return self._send(200, {"access_token": access,
                                    "token_type": "Bearer",
                                    "expires_in": ACCESS_TOKEN_TTL,
                                    "refresh_token": refresh,
                                    "scope": scope,
                                    **({"key_handoff": v["key_handoff"]}
                                       if v.get("key_handoff") else {})})
        if grant == "refresh_token":
            rt = params.get("refresh_token", "")
            rh = hashlib.sha256(rt.encode()).hexdigest()
            with _lock:
                now = time.time()
                d = load_oauth()
                v = None
                for k, vv in d["refresh"].items():
                    if hmac.compare_digest(k, rh):
                        v = vv
                        break
                if (not v or v.get("exp", 0) <= now or
                        v.get("client_id") != client_id):
                    return self._oauth_error(400, "invalid_grant")
                access, refresh = _issue_token_pair(d, v["agent"], client_id,
                                                   v.get("scope", "relay"))
                save_oauth(d)
            return self._send(200, {"access_token": access,
                                    "token_type": "Bearer",
                                    "expires_in": ACCESS_TOKEN_TTL,
                                    "refresh_token": refresh,
                                    "scope": v.get("scope", "relay")})
        return self._oauth_error(400, "unsupported_grant_type")

    def _handle_revoke(self):
        agent = self._auth()
        if not agent:
            return self._send(401, {"ok": False, "error": "unauthorized"})
        params = self._read_params()
        token = params.get("token", "")
        if not token:
            return self._send(400, {"ok": False, "error": "bad_token"})
        digest = hashlib.sha256(token.encode()).hexdigest()
        with _lock:
            d = load_oauth()
            access = d["access"].get(digest)
            # Follow the pair's existing link, never all tokens for an agent.
            # Reverse lookup also works after an expired access row is pruned.
            for rh, refresh in list(d["refresh"].items()):
                if refresh.get("agent") != agent:
                    continue
                linked = refresh.get("access_hash") == digest and (
                    access is None or (access.get("agent") == agent and
                    access.get("client_id") == refresh.get("client_id")))
                if rh != digest and not linked:
                    continue
                ah = refresh.get("access_hash")
                paired = d["access"].get(ah)
                if (paired and paired.get("agent") == agent and
                        paired.get("client_id") == refresh.get("client_id")):
                    del d["access"][ah]
                del d["refresh"][rh]
            if access and access.get("agent") == agent:
                d["access"].pop(digest, None)
            save_oauth(d)
        return self._send(200, {"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, {"ok": True, "ts": int(time.time())})
        if parsed.path == "/login":
            qs = parse_qs(parsed.query)
            nxt = qs.get("next", [""])[0]
            return self._serve_login_page(nxt=nxt if valid_next(nxt) else "")
        if parsed.path == "/oauth/device":
            return self._handle_device_page(parse_qs(parsed.query))
        if parsed.path == "/app":
            agent = get_session_agent(self.headers.get("Cookie"))
            if not agent:
                return self._redirect("/login")
            return self._serve_app(agent)
        if parsed.path == "/v1/me":
            agent = self._auth()
            if not agent:
                return self._send(401, {"ok": False, "error": "unauthorized"})
            return self._send(200, {"ok": True, "agent": agent})
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
        if parsed.path == "/logout":
            return self._logout()
        if parsed.path == "/login":
            ip = self.client_address[0]
            form = self._read_form()
            nxt = ""
            if form:
                nxt = form.get("next", [""])[0] or ""
            nxt = nxt if valid_next(nxt) else ""
            if login_rate_limited(ip):
                return self._serve_login_page("尝试次数过多，请 10 分钟后再试。", nxt)
            if not form:
                return self._serve_login_page("请求无效，请重试。", nxt)
            username = (form.get("username", [""])[0] or "").strip()[:64]
            password = form.get("password", [""])[0] or ""
            if username and password and check_password(username, password):
                sid = secrets.token_urlsafe(32)
                with _lock:
                    _sessions[sid] = {"agent": username,
                                      "exp": time.time() + SESSION_TTL}
                    save_sessions()
                return self._serve_login_done(sid, nxt)
            time.sleep(1)
            return self._serve_login_page("用户名或密码错误。", nxt)
        if parsed.path == "/oauth/device/code":
            return self._handle_device_code()
        if parsed.path == "/oauth/device/verify":
            return self._handle_device_verify()
        if parsed.path == "/oauth/device/authorize":
            return self._handle_device_authorize()
        if parsed.path == "/oauth/token":
            return self._handle_token()
        if parsed.path == "/oauth/revoke":
            return self._handle_revoke()
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
            n = ack_ids(agent, [str(i) for i in ids])
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
            try:
                prune_oauth()
            except Exception:
                pass

    threading.Thread(target=janitor, daemon=True).start()
    print("relay listening on 0.0.0.0:%d tls=%s" % (port, tls_on), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
