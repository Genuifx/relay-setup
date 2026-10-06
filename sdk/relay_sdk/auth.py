"""OAuth 2.0 Device Authorization Grant (RFC 8628) + local token store.

The agent never handles the user's password: it shows a user_code, the
human authorizes it at the verification URI in a browser, the agent polls
for tokens. Access tokens auto-refresh via the stored refresh token.
"""
import http.client
import json
import math
import re
import os
import ssl
import tempfile
import time
from urllib.parse import urlparse
from .transport import https_connection

DEFAULT_CLIENT_ID = "relay-cli"


class TokenStore:
    """JSON file holding OAuth tokens (and optionally the E2EE key)."""

    def __init__(self, path=None):
        if path is None:
            path = os.environ.get("RELAY_CLI_CONFIG") or os.path.expanduser(
                "~/.config/relay-cli/config.json")
        self.path = path
        self.data = {}
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except (FileNotFoundError, ValueError):
            self.data = {}

    def save(self):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        # mkstemp creates exclusively with mode 0600 before any secret is written.
        fd, tmp = tempfile.mkstemp(prefix=".relay-config-", dir=d or ".")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def clear_tokens(self):
        for k in ("access_token", "refresh_token", "access_expires_at"):
            self.data.pop(k, None)
        self.save()

    @property
    def server(self):
        return self.data.get("server")

    @property
    def agent(self):
        return self.data.get("agent")


def _post_form(server, path, params, timeout=25):
    target = urlparse(server)
    body = "&".join("%s=%s" % (k, _quote(v)) for k, v in params.items())
    if target.scheme == "https":
        conn = https_connection(target, timeout)
    else:
        conn = http.client.HTTPConnection(target.hostname, target.port or 80,
                                          timeout=timeout)
    try:
        conn.request("POST", path, body=body.encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = conn.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw.decode() or "{}")
        except ValueError:
            return r.status, {"_raw": raw[:200].decode(errors="replace")}
    finally:
        conn.close()


def _quote(s):
    from urllib.parse import quote
    return quote(str(s), safe="")


def _secure_origin(url):
    try:
        target = urlparse(url)
        if (target.scheme != "https" or not target.hostname or target.username is not None
                or target.password is not None or target.query or target.fragment
                or any(c.isspace() for c in url)):
            raise ValueError()
        return target.hostname.lower(), target.port or 443
    except (ValueError, TypeError):
        raise RuntimeError("Key handoff requires a valid HTTPS URL without credentials, query or fragment") from None


def device_login(server, client_id=DEFAULT_CLIENT_ID, scope="relay", out=None):
    """Legacy token-only device flow; returns (access, refresh, expires_in).

    This API remains compatible. Use device_login_with_key for browser key entry.
    """
    tokens, _ = _device_login(server, client_id, scope, out, receiver=None)
    return tokens["access_token"], tokens.get("refresh_token"), tokens.get("expires_in", 0)


def device_login_with_key(server, client_id=DEFAULT_CLIENT_ID, scope="relay", out=None):
    """HTTPS browser key handoff; returns (access, refresh, expiry, key, agent).

    Fails closed on unsupported servers. Validates the encrypted request/identity
    binding and checks the token's identity before returning any local key.
    """
    _secure_origin(server)
    if urlparse(server).path not in ("", "/"):
        raise RuntimeError("Key handoff requires an HTTPS relay base URL")
    from .key_handoff import KeyReceiver
    from .client import RelayClient, RelayError
    receiver = KeyReceiver()
    tokens, device = _device_login(server, client_id, scope, out, receiver)
    key, agent = receiver.unwrap(tokens.get("key_handoff"), device["device_code"], client_id)
    try:
        token_agent = RelayClient(server, tokens["access_token"]).me()
    except (RelayError, ValueError, OSError, http.client.HTTPException):
        raise RuntimeError("Token identity verification failed; check HTTPS and restart login") from None
    if token_agent != agent:
        raise RuntimeError("E2EE key handoff identity mismatch; restart login")
    return tokens["access_token"], tokens["refresh_token"], tokens["expires_in"], key, agent


def _device_login(server, client_id, scope, out, receiver):
    emit = out or print
    params = {"client_id": client_id, "scope": scope}
    if receiver:
        from .key_handoff import ALGORITHM
        params.update(key_handoff_alg=ALGORITHM,
                      key_handoff_public_key=json.dumps(receiver.public_key))
    st, d = _post_form(server, "/oauth/device/code", params)
    if st != 200 or not isinstance(d, dict) or not d.get("device_code"):
        raise RuntimeError("device/code failed; restart login")
    if receiver:
        if d.get("key_handoff_alg") != ALGORITHM:
            raise RuntimeError("Server does not support secure key handoff; upgrade it or explicitly use login --tokens-only and set-key")
        for field, default in (("expires_in", 600), ("interval", 5)):
            value = d.get(field, default)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 600:
                raise RuntimeError("Invalid device response timing; restart login")
        if not isinstance(d.get("user_code"), str) or not re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", d["user_code"]):
            raise RuntimeError("Invalid device response code; restart login")
        if not isinstance(d["device_code"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", d["device_code"]):
            raise RuntimeError("Invalid device response code; restart login")
        uri = d.get("verification_uri")
        if not isinstance(uri, str) or _secure_origin(uri) != _secure_origin(server) or urlparse(uri).path != "/oauth/device":
            raise RuntimeError("Unsafe key-entry verification URI; check relay configuration")
    emit("请在浏览器打开（10 分钟内有效）：")
    emit("  " + d["verification_uri"])
    emit("输入并核对这组代码：  " + d["user_code"])
    emit("（登录后在浏览器输入现有 E2EE 密钥并授权）" if receiver else
         "（未登录会先让你登录；登录后点“授权”即可）")
    interval = d.get("interval", 5)
    deadline = time.time() + d.get("expires_in", 600)
    while time.time() < deadline:
        time.sleep(interval)
        st, t = _post_form(server, "/oauth/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id, "device_code": d["device_code"]})
        if not isinstance(t, dict):
            raise RuntimeError("Invalid token response; restart login")
        err = t.get("error")
        if err in ("authorization_pending", "slow_down"):
            if err == "slow_down":
                interval += 5
            continue
        if err or st != 200:
            # Do not echo server-controlled descriptions or token response bodies.
            reason = err if err in ("access_denied", "expired_token", "invalid_grant") else "token request failed"
            raise RuntimeError("授权失败: %s; restart login" % reason)
        if not isinstance(t.get("access_token"), str) or not t["access_token"]:
            raise RuntimeError("Invalid token response; restart login")
        if receiver:
            for field in ("access_token", "refresh_token"):
                value = t.get(field)
                if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value):
                    raise RuntimeError("Invalid token response; restart login")
            expiry = t.get("expires_in")
            if type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= 0:
                raise RuntimeError("Invalid token response; restart login")
        return t, d
    raise RuntimeError("授权超时，请重新发起 login")


def refresh_access_token(server, refresh_token, client_id=DEFAULT_CLIENT_ID):
    st, d = _post_form(server, "/oauth/token", {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token})
    if st != 200 or "access_token" not in d:
        raise RuntimeError("refresh failed: %r %r" % (st, d))
    return d["access_token"], d.get("refresh_token"), d.get("expires_in", 0)


def get_valid_token(store, server=None, client_id=DEFAULT_CLIENT_ID):
    """Return a usable access token, refreshing transparently if needed."""
    server = server or store.server
    if not server:
        raise RuntimeError("no server configured; run `relay-cli login` first")
    data = store.data
    if data.get("access_token") and data.get("access_expires_at", 0) > time.time() + 60:
        return data["access_token"]
    if not data.get("refresh_token"):
        raise RuntimeError("no valid token; run `relay-cli login` first")
    access, refresh, expires_in = refresh_access_token(
        server, data["refresh_token"], client_id)
    data["access_token"] = access
    if refresh:
        data["refresh_token"] = refresh
    data["access_expires_at"] = time.time() + expires_in
    data["server"] = server
    store.save()
    return access
