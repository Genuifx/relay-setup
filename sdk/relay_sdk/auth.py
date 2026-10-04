"""OAuth 2.0 Device Authorization Grant (RFC 8628) + local token store.

The agent never handles the user's password: it shows a user_code, the
human authorizes it at the verification URI in a browser, the agent polls
for tokens. Access tokens auto-refresh via the stored refresh token.
"""
import http.client
import json
import os
import ssl
import time
from urllib.parse import urlparse

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
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

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
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(target.hostname, target.port or 443,
                                           timeout=timeout, context=ctx)
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


def device_login(server, client_id=DEFAULT_CLIENT_ID, scope="relay",
                 out=None):
    """Run the device flow. Returns (access_token, refresh_token, expires_in).

    Prints instructions for the human; blocks until they approve/deny or
    the device code expires.
    """
    emit = out or print
    st, d = _post_form(server, "/oauth/device/code",
                       {"client_id": client_id, "scope": scope})
    if st != 200 or "device_code" not in d:
        raise RuntimeError("device/code failed: %r %r" % (st, d))
    emit("请在浏览器打开（10 分钟内有效）：")
    emit("  " + d["verification_uri"])
    emit("输入这组代码：  " + d["user_code"])
    emit("（未登录会先让你登录；登录后点“授权”即可）")
    interval = d.get("interval", 5)
    deadline = time.time() + d.get("expires_in", 600)
    while time.time() < deadline:
        time.sleep(interval)
        st, t = _post_form(server, "/oauth/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": d["device_code"]})
        err = t.get("error")
        if err in ("authorization_pending", "slow_down"):
            if err == "slow_down":
                interval += 5
            continue
        if err:
            raise RuntimeError("授权失败: %s" % err)
        return t["access_token"], t.get("refresh_token"), t.get("expires_in", 0)
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
