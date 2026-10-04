"""HTTPS JSON API client for the relay.

Direct TLS with system CA verification. Pass a Bearer token (static token
or an OAuth access token from relay_sdk.auth).
"""
import http.client
import json
import ssl
import time
from urllib.parse import urlparse, quote


class RelayError(Exception):
    pass


class RelayClient:
    def __init__(self, base_url, token, timeout=25):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method, path, body=None, retries=3):
        target = urlparse(self.base_url)
        use_tls = target.scheme == "https"
        last = None
        for attempt in range(retries):
            conn = None
            try:
                if use_tls:
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(
                        target.hostname, target.port or 443,
                        timeout=self.timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(
                        target.hostname, target.port or 80,
                        timeout=self.timeout)
                headers = {"Authorization": "Bearer %s" % self.token,
                           "Content-Type": "application/json"}
                data = json.dumps(body).encode() if body is not None else None
                conn.request(method, path, body=data, headers=headers)
                r = conn.getresponse()
                raw = r.read()
                try:
                    d = json.loads(raw.decode() or "{}")
                except ValueError:
                    d = {"_raw": raw[:200].decode(errors="replace")}
                if r.status == 401:
                    raise RelayError("unauthorized (401)")
                return r.status, d
            except RelayError:
                raise
            except Exception as e:
                last = e
                time.sleep(2 * (attempt + 1))
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        raise RelayError("request failed after %d attempts: %r" % (retries, last))

    def me(self):
        st, d = self._request("GET", "/v1/me")
        if st != 200 or not d.get("ok"):
            raise RelayError("me failed: %r %r" % (st, d))
        return d["agent"]

    def send(self, to, type, payload_b64, ttl_hours=168):
        st, d = self._request("POST", "/v1/send",
                              {"to": to, "type": type, "payload": payload_b64,
                               "ttl_hours": ttl_hours})
        if st != 200 or not d.get("ok"):
            raise RelayError("send failed: %r %r" % (st, d))
        return d

    def inbox(self, since=""):
        st, d = self._request("GET", "/v1/inbox?since=%s" % quote(since, safe=""))
        if st != 200 or not d.get("ok"):
            raise RelayError("inbox failed: %r %r" % (st, d))
        return d["messages"]

    def ack(self, ids):
        st, d = self._request("POST", "/v1/ack", {"ids": list(ids)})
        if st != 200 or not d.get("ok"):
            raise RelayError("ack failed: %r %r" % (st, d))
        return d["deleted"]

    def revoke_token(self, token):
        st, d = self._request("POST", "/oauth/revoke", {"token": token})
        if st != 200 or not d.get("ok"):
            raise RelayError("revoke failed: %r %r" % (st, d))
        return True
