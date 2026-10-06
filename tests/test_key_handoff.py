"""Key handoff regressions: fake credentials, in-memory HTTP, local Web Crypto."""
import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor
import html
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import unittest
from unittest import mock
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from test_security import RelayTestCase, MemorySocket, relay, auth, cli

ALG = "RSA-OAEP-256"
KEY = bytes(range(32))  # Deliberately fake test key.
KEY_B64 = base64.urlsafe_b64encode(KEY).decode()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def label(dc, client_id="relay-cli", agent="agent-a"):
    return json.dumps(["relay-e2ee-handoff-v1", dc, client_id, agent],
                      separators=(",", ":"), ensure_ascii=False).encode()


class FormParser(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.inputs = {}
        self.scripts = {}
        self.current = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            self.inputs[attrs.get("name") or attrs.get("id")] = attrs
        if tag == "script":
            self.current = attrs.get("id", "script")
            self.scripts[self.current] = ""

    def handle_endtag(self, tag):
        if tag == "script":
            self.current = None

    def handle_data(self, data):
        if self.current is not None:
            self.scripts[self.current] += data


class KeyHandoffTests(RelayTestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        n = cls.private.public_key().public_numbers().n.to_bytes(384, "big")
        cls.jwk = {"kty": "RSA", "alg": ALG, "n": b64url(n), "e": "AQAB"}

    def setUp(self):
        super().setUp()
        relay._sessions["test-session-a"] = {"agent": "agent-a", "exp": time.time() + 600}
        relay._sessions["test-session-b"] = {"agent": "agent-b", "exp": time.time() + 600}

    def request(self, method, path, body=None, token=None, headers=None):
        headers = dict(headers or {})
        if token:
            headers["Authorization"] = "Bearer " + token
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            body = body.encode()
        body = body or b""
        headers["Content-Length"] = str(len(body))
        raw = (method + " " + path + " HTTP/1.0\r\nHost: relay.test\r\n" +
               "".join(k + ": " + v + "\r\n" for k, v in headers.items()) + "\r\n").encode() + body
        sock = MemorySocket(raw)
        relay.Handler(sock, ("127.0.0.1", 10000), object())
        head, payload = bytes(sock.response).split(b"\r\n\r\n", 1)
        self.last_headers = head.decode()
        status = int(head.split(b" ", 2)[1])
        if b"Content-Type: application/json" in head:
            return status, json.loads(payload)
        return status, payload.decode()

    def start(self, **extra):
        params = {"client_id": "relay-cli", "key_handoff_alg": ALG,
                  "key_handoff_public_key": json.dumps(self.jwk)}
        params.update(extra)
        status, data = self.request("POST", "/oauth/device/code", params)
        self.assertEqual(status, 200)
        return data

    def consent(self, d, session="test-session-a"):
        status, page = self.request("GET", "/oauth/device?code=" + d["user_code"],
                                   headers={"Cookie": "relay_session=" + session})
        self.assertEqual(status, 200)
        form = FormParser(page)
        self.assertIn("csrf_token", form.inputs, "consent must bind this browser session")
        return form

    def encrypt(self, d, agent="agent-a", private=None):
        ct = (private or self.private).public_key().encrypt(KEY, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
            label=label(d["device_code"], agent=agent)))
        return base64.b64encode(ct).decode()

    def approve(self, d, session="test-session-a", ciphertext=None, **extra):
        form = self.consent(d, session)
        params = {"device_code": d["device_code"], "action": "approve",
                  "csrf_token": form.inputs["csrf_token"]["value"],
                  "key_handoff": ciphertext or self.encrypt(d)}
        params.update(extra)
        return self.request("POST", "/oauth/device/authorize", urlencode(params),
                            headers={"Cookie": "relay_session=" + session,
                                     "Content-Type": "application/x-www-form-urlencoded"})

    def poll(self, d, client_id="relay-cli"):
        return self.request("POST", "/oauth/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id, "device_code": d["device_code"]})

    def test_server_negotiates_and_delivers_ciphertext_only_once(self):
        d = self.start()
        self.assertEqual(d.get("key_handoff_alg"), ALG)
        encrypted = self.encrypt(d)
        self.approve(d, ciphertext=encrypted)
        stored = Path(relay.OAUTH_STORE).read_text()
        self.assertNotIn(KEY_B64, stored)
        self.assertIn(encrypted, stored)
        status, result = self.poll(d)
        self.assertEqual(status, 200)
        self.assertEqual(result["key_handoff"], {
            "alg": ALG, "ciphertext": encrypted, "agent": "agent-a"})
        self.assertNotIn(encrypted, Path(relay.OAUTH_STORE).read_text())
        self.assertNotIn(KEY_B64, json.dumps(result))
        self.assertEqual(self.poll(d)[1]["error"], "invalid_grant")
        refreshed = self.refresh(result["refresh_token"])
        self.assertEqual(refreshed[0], 200)
        self.assertNotIn("key_handoff", refreshed[1])

    def test_invalid_public_keys_are_rejected_without_creating_requests(self):
        for key in ("garbage", {}, dict(self.jwk, d="private"),
                    dict(self.jwk, e="Aw"), dict(self.jwk, n="A" * 512)):
            with self.subTest(key_type=type(key).__name__):
                status, result = self.request("POST", "/oauth/device/code", {
                    "client_id": "relay-cli", "key_handoff_alg": ALG,
                    "key_handoff_public_key": json.dumps(key)})
                self.assertEqual((status, result.get("error")), (400, "invalid_request"))
        self.assertEqual(relay.load_oauth()["device"], {})

    def test_handoff_requires_supported_algorithm_and_complete_parameters(self):
        for params in ({"key_handoff_alg": ALG},
                       {"key_handoff_public_key": json.dumps(self.jwk)},
                       {"key_handoff_alg": "plain", "key_handoff_public_key": json.dumps(self.jwk)}):
            status, result = self.request("POST", "/oauth/device/code", {"client_id": "relay-cli", **params})
            self.assertEqual((status, result.get("error")), (400, "invalid_request"))

    def test_consent_has_password_without_name_and_no_store_headers(self):
        d = self.start()
        form = self.consent(d)
        self.assertEqual(form.inputs["handoff-key"]["type"], "password")
        self.assertNotIn("name", form.inputs["handoff-key"])
        self.assertEqual(form.inputs["handoff-key"]["autocomplete"], "off")
        self.assertIn("Cache-Control: no-store", self.last_headers)
        self.assertIn("Referrer-Policy: no-referrer", self.last_headers)
        self.assertIn("frame-ancestors 'none'", self.last_headers)
        data = json.loads(form.scripts["handoff-data"])
        self.assertEqual(data["public_key"], self.jwk)
        self.assertEqual(data["label"], json.loads(label(d["device_code"])))

    def test_csrf_and_different_session_cannot_authorize_request(self):
        d = self.start()
        form = self.consent(d)
        good = form.inputs["csrf_token"]["value"]
        for session, csrf in (("test-session-a", ""), ("test-session-a", "bad"),
                              ("test-session-b", good)):
            status, _ = self.request("POST", "/oauth/device/authorize", urlencode({
                "device_code": d["device_code"], "action": "approve",
                "csrf_token": csrf, "key_handoff": self.encrypt(d)}),
                headers={"Cookie": "relay_session=" + session})
            self.assertEqual(status, 403)
            self.assertEqual(relay.load_oauth()["device"][d["device_code"]]["status"], "pending")

    def test_missing_or_malformed_envelope_does_not_approve(self):
        for ciphertext in ("", KEY_B64, "!" * 512, base64.b64encode(b"x" * 383).decode()):
            d = self.start()
            status, _ = self.approve(d, key_handoff=ciphertext)
            self.assertEqual(status, 400)
            self.assertEqual(relay.load_oauth()["device"][d["device_code"]]["status"], "pending")

    def test_deny_and_expiry_never_deliver_key(self):
        d = self.start()
        self.approve(d, action="deny", key_handoff="")
        self.assertEqual(self.poll(d)[1]["error"], "access_denied")
        d = self.start()
        self.approve(d)
        data = relay.load_oauth()
        data["device"][d["device_code"]]["exp"] = time.time() - 1
        relay.save_oauth(data)
        self.assertEqual(self.poll(d)[1]["error"], "expired_token")
        self.assertNotIn(d["device_code"], relay.load_oauth()["device"])

    def test_poll_waiting_for_lock_cannot_redeem_expired_handoff(self):
        d = self.start()
        self.approve(d)
        expiry = relay.load_oauth()["device"][d["device_code"]]["exp"]
        clock = [expiry - 1]
        lock = relay._lock
        class DelayedLock:
            def __enter__(self):
                lock.acquire()
                clock[0] = expiry + 1
            def __exit__(self, *args):
                lock.release()
        with mock.patch.object(relay.time, "time", side_effect=lambda: clock[0]):
            with mock.patch.object(relay, "_lock", DelayedLock()):
                status, data = self.poll(d)
        self.assertEqual((status, data.get("error")), (400, "expired_token"))
        self.assertNotIn("key_handoff", data)

    def test_concurrent_poll_has_only_one_key_delivery(self):
        d = self.start()
        self.approve(d)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.poll(d), range(2)))
        self.assertEqual(sorted(status for status, _ in results), [200, 400])
        self.assertEqual(sum("key_handoff" in data for _, data in results), 1)

    def test_legacy_device_flow_still_works_without_handoff(self):
        status, d = self.request("POST", "/oauth/device/code", {"client_id": "relay-cli"})
        self.assertEqual(status, 200)
        form = self.consent(d)
        self.assertNotIn("handoff-key", form.inputs)
        self.request("POST", "/oauth/device/authorize", urlencode({
            "device_code": d["device_code"], "action": "approve",
            "csrf_token": form.inputs["csrf_token"]["value"]}),
            headers={"Cookie": "relay_session=test-session-a"})
        status, result = self.poll(d)
        self.assertEqual(status, 200)
        self.assertNotIn("key_handoff", result)

    def test_sdk_rejects_insecure_transport_before_request(self):
        self.assertTrue(hasattr(auth, "device_login_with_key"), "new secure login API is missing")
        with mock.patch.object(auth, "_post_form") as post:
            for server in ("http://relay.test", "https://user:pass@relay.test", "https://relay.test/?secret=x"):
                with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                    auth.device_login_with_key(server, out=lambda x: None)
            post.assert_not_called()

    def test_sdk_does_not_silently_downgrade_old_server(self):
        self.assertTrue(hasattr(auth, "device_login_with_key"), "new secure login API is missing")
        with mock.patch.object(auth, "_post_form", return_value=(200, {
                "device_code": "fake-device", "user_code": "AAAA-BBBB",
                "verification_uri": "https://relay.test/oauth/device", "expires_in": 600})):
            with self.assertRaisesRegex(RuntimeError, "tokens-only"):
                auth.device_login_with_key("https://relay.test", out=lambda x: None)

    def browser_connection(self, transform=None, me_agent=None, lose_token=False):
        connection = self.connection_class()
        harness = self

        class BrowserApproval(connection):
            def request(self, method, path, body=None, headers=None):
                self.path = path
                super().request(method, path, body, headers)
                if path == "/oauth/device/code":
                    d = self.result[1]
                    record = relay.load_oauth()["device"][d["device_code"]]
                    harness.assertIn("key_handoff_public_key", record,
                                     "CLI must request encrypted key handoff")
                    jwk = record["key_handoff_public_key"]
                    public = rsa.RSAPublicNumbers(65537, int.from_bytes(
                        base64.urlsafe_b64decode(jwk["n"] + "=="), "big")).public_key()
                    ciphertext = base64.b64encode(public.encrypt(KEY, padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                        label=label(d["device_code"])))) .decode()
                    harness.approve(d, ciphertext=ciphertext)
                if path == "/oauth/token" and transform:
                    transform(self.result[1])
                if path == "/v1/me" and me_agent:
                    self.result[1]["agent"] = me_agent

            def getresponse(self):
                if self.path == "/oauth/token" and lose_token:
                    raise TimeoutError("simulated token response loss")
                return super().getresponse()

        return BrowserApproval

    def test_cli_saves_tokens_and_decrypted_key_in_one_private_config(self):
        config = str(Path(self.tmp.name) / "client.json")
        BrowserApproval = self.browser_connection()
        output = io.StringIO()
        with mock.patch("http.client.HTTPSConnection", BrowserApproval), mock.patch.object(auth.time, "sleep"):
            with contextlib.redirect_stdout(output):
                cli.main(["--server", "https://relay.test", "--config", config, "login"])
        saved = json.loads(Path(config).read_text())
        self.assertEqual(saved["e2e_key"], KEY_B64)
        self.assertEqual(saved["agent"], "agent-a")
        self.assertEqual(relay.bearer_agent(saved["access_token"]), "agent-a")
        self.assertEqual(stat.S_IMODE(os.stat(config).st_mode), 0o600)
        self.assertNotIn(KEY_B64, output.getvalue())
        self.assertNotIn("PRIVATE KEY", Path(config).read_text())

    def test_consent_rejects_non_ascii_csrf_without_crashing(self):
        d = self.start()
        self.assertEqual(self.approve(d, csrf_token="无效")[0], 403)

    def test_consent_rejects_other_device_token_and_expired_session(self):
        d1, d2 = self.start(), self.start()
        csrf = self.consent(d1).inputs["csrf_token"]["value"]
        self.assertEqual(self.approve(d2, csrf_token=csrf)[0], 403)
        relay._sessions["test-session-a"]["exp"] = time.time() - 1
        status, _ = self.request("POST", "/oauth/device/authorize", urlencode({
            "device_code": d1["device_code"], "action": "approve", "csrf_token": csrf,
            "key_handoff": self.encrypt(d1)}), headers={"Cookie": "relay_session=test-session-a"})
        self.assertEqual(status, 401)
        self.assertEqual(relay.load_oauth()["device"][d1["device_code"]]["status"], "pending")

    def test_unknown_action_and_repeated_approval_cannot_replace_key(self):
        d = self.start()
        self.assertEqual(self.approve(d, action="unknown")[0], 400)
        encrypted = self.encrypt(d)
        form = self.consent(d)
        params = {"device_code": d["device_code"], "action": "approve",
                  "csrf_token": form.inputs["csrf_token"]["value"], "key_handoff": encrypted}
        for ciphertext in (encrypted, base64.b64encode(b"x" * 384).decode()):
            params["key_handoff"] = ciphertext
            self.request("POST", "/oauth/device/authorize", urlencode(params),
                         headers={"Cookie": "relay_session=test-session-a"})
        self.assertEqual(self.poll(d)[1]["key_handoff"]["ciphertext"], encrypted)

    def test_sdk_rejects_cross_origin_verification_without_emitting_link(self):
        emitted = []
        for uri in ("https://other.test/oauth/device", "https://relay.test:444/oauth/device",
                    "http://relay.test/oauth/device", "https://relay.test/oauth/device?key=x"):
            with mock.patch.object(auth, "_post_form", return_value=(200, {
                    "device_code": "test-device", "user_code": "AAAA-BBBB", "key_handoff_alg": ALG,
                    "verification_uri": uri})):
                with self.assertRaises(RuntimeError):
                    auth.device_login_with_key("https://relay.test", out=emitted.append)
        self.assertEqual(emitted, [])

    def test_invalid_bearer_never_reaches_http_headers_or_error_output(self):
        secret = "fake-token-must-stay-secret\n"
        public = [None]
        def post(server, path, params):
            if path == "/oauth/device/code":
                jwk = json.loads(params["key_handoff_public_key"])
                public[0] = rsa.RSAPublicNumbers(65537, int.from_bytes(
                    base64.urlsafe_b64decode(jwk["n"]), "big")).public_key()
                return 200, {"device_code": "fake-device", "user_code": "AAAA-BBBB",
                             "key_handoff_alg": ALG, "verification_uri": "https://relay.test/oauth/device"}
            ciphertext = public[0].encrypt(KEY, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label("fake-device")))
            return 200, {"access_token": secret, "refresh_token": "fake-refresh", "expires_in": 3600,
                         "key_handoff": {"alg": ALG, "agent": "agent-a",
                                         "ciphertext": base64.b64encode(ciphertext).decode()}}
        with mock.patch.object(auth, "_post_form", post), mock.patch.object(auth.time, "sleep"):
            with mock.patch("http.client.HTTPSConnection.connect", side_effect=AssertionError("no network")):
                try:
                    auth.device_login_with_key("https://relay.test", out=lambda _: None)
                except Exception as error:
                    self.assertIsInstance(error, RuntimeError, "malformed tokens must fail before HTTP header creation")
                    self.assertNotIn(secret.strip(), str(error))
                else:
                    self.fail("invalid token accepted")

    def test_handoff_rejects_nonfinite_and_boolean_lifetimes(self):
        for value in (float("nan"), float("inf"), True):
            connection = self.browser_connection(transform=lambda t: t.update(expires_in=value))
            with mock.patch("http.client.HTTPSConnection", connection), mock.patch.object(auth.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "token response"):
                    auth.device_login_with_key("https://relay.test", out=lambda _: None)

    def test_handoff_rejects_invalid_poll_timing_before_display(self):
        emitted = []
        for field, value in (("interval", -1), ("interval", 0), ("interval", float("nan")),
                             ("expires_in", float("inf")), ("expires_in", True)):
            data = {"device_code": "fake-device", "user_code": "AAAA-BBBB", "key_handoff_alg": ALG,
                    "verification_uri": "https://relay.test/oauth/device", "interval": 5, "expires_in": 600,
                    field: value}
            with mock.patch.object(auth, "_post_form", return_value=(200, data)):
                with self.assertRaises(RuntimeError):
                    auth.device_login_with_key("https://relay.test", out=emitted.append)
        self.assertEqual(emitted, [])

    def test_cli_failures_leave_previous_config_bytes_unchanged(self):
        changes = [lambda t: t.pop("key_handoff"),
                   lambda t: t["key_handoff"].update(ciphertext="!" * 512),
                   lambda t: t["key_handoff"].update(agent="agent-b"),
                   lambda t: t.update(access_token=None)]
        config = str(Path(self.tmp.name) / "client.json")
        original = '{"e2e_key":"previous-fake-key","access_token":"previous-fake-token"}'
        for change in changes + [None]:
            Path(config).write_text(original)
            connection = self.browser_connection(transform=change, me_agent="agent-b" if change is None else None)
            with mock.patch("http.client.HTTPSConnection", connection), mock.patch.object(auth.time, "sleep"):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        cli.main(["--server", "https://relay.test", "--config", config, "login"])
            self.assertEqual(Path(config).read_text(), original)

    def test_lost_token_response_and_save_failure_preserve_config(self):
        config = str(Path(self.tmp.name) / "client.json")
        original = '{"e2e_key":"previous-fake-key"}'
        for lose_response in (True, False):
            Path(config).write_text(original)
            connection = self.browser_connection(lose_token=lose_response)
            save = contextlib.nullcontext()
            # Patch only TokenStore.save to simulate its real atomic-save failure;
            # relay os.replace shares Python's os module with auth.
            if not lose_response:
                real_save = auth.TokenStore.save
                def fail_save(store):
                    with mock.patch.object(auth.os, "replace", side_effect=OSError("disk full")):
                        real_save(store)
                save = mock.patch.object(auth.TokenStore, "save", fail_save)
            with mock.patch("http.client.HTTPSConnection", connection), mock.patch.object(auth.time, "sleep"), save:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        cli.main(["--server", "https://relay.test", "--config", config, "login"])
            self.assertEqual(Path(config).read_text(), original)
            self.assertFalse(list(Path(self.tmp.name).glob(".relay-config-*")))

    def test_webcrypto_script_binds_labels_and_waits_for_parsed_dom(self):
        # Run the exact served script with real Web Crypto, fake DOM, no sockets.
        self.assertIsNotNone(shutil.which("node"), "Node.js is required for Web Crypto regression tests")
        from relay_sdk.key_handoff import KeyReceiver
        receiver = KeyReceiver()
        d = self.start(key_handoff_public_key=json.dumps(receiver.public_key))
        relay._sessions["test-session-a"]["agent"] = "代理-ä</script>"
        form = self.consent(d)
        self.assertNotIn("</script>", form.scripts["handoff-data"])
        js = form.scripts["script"]
        # The inline script is physically before the approval button in HTML.
        # document.getElementById('approve-button') must wait for DOMContentLoaded.
        script = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let ready = false;
let onReady;
let submit;
let nativeSubmissions = 0;
let appendedAction;
const fields = {
  'consent-form': {addEventListener: (_, fn) => { submit = fn; },
    appendChild: action => { appendedAction = action; }, submit: () => { nativeSubmissions++; }},
  'handoff-key': {value: input.key}, 'key-handoff': {value: ''},
  'handoff-error': {textContent: ''}, 'approve-button': {disabled: false},
  'handoff-data': {textContent: JSON.stringify(input.data)}
};
global.window = {isSecureContext: true, addEventListener: () => {}};
global.document = {
  getElementById: id => (!ready && id === 'approve-button') ? null : fields[id],
  addEventListener: (_, fn) => { onReady = fn; }, createElement: () => ({})
};
(async () => {
  eval(input.script);
  ready = true;
  if (onReady) onReady();
  let prevented = false;
  await submit({submitter: {value: 'approve'}, preventDefault: () => { prevented = true; }});
  if (!prevented || nativeSubmissions !== 1 || appendedAction.value !== 'approve' ||
      fields['handoff-key'].value !== '') throw new Error('unsafe submit');
  process.stdout.write(fields['key-handoff'].value);
})().catch(e => { console.error(e.message); process.exit(1); });
"""
        result = subprocess.run(["node", "-e", script], input=json.dumps({
            "script": js, "data": json.loads(form.scripts["handoff-data"]), "key": KEY_B64}),
            text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        envelope = {"alg": ALG, "ciphertext": result.stdout, "agent": "代理-ä</script>"}
        self.assertEqual(receiver.unwrap(envelope, d["device_code"], "relay-cli"), (KEY_B64, envelope["agent"]))
        for dc, client_id, agent in (("different-device", "relay-cli", envelope["agent"]),
                                     (d["device_code"], "different-client", envelope["agent"]),
                                     (d["device_code"], "relay-cli", "agent-b")):
            with self.assertRaisesRegex(RuntimeError, "handoff failed"):
                receiver.unwrap(dict(envelope, agent=agent), dc, client_id)

    def test_browser_cancel_repeat_invalid_key_and_history_restore(self):
        d = self.start()
        form = self.consent(d)
        script = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const vm = require('vm');
const realCrypto = globalThis.crypto;
async function scenario(mode) {
  let ready, submit, release;
  const windowEvents = {};
  let encryptCalls = 0, nativeSubmissions = 0, reloads = 0;
  const fields = {
    'consent-form': {addEventListener: (_, fn) => { submit = fn; },
      appendChild: () => {}, submit: () => { nativeSubmissions++; }},
    'handoff-key': {value: mode === 'invalid' ? 'not-a-key' : input.key},
    'key-handoff': {value: ''}, 'handoff-error': {textContent: ''},
    'approve-button': {disabled: false},
    'handoff-data': {textContent: JSON.stringify(input.data)}
  };
  const pause = new Promise(resolve => { release = resolve; });
  const context = vm.createContext({Uint8Array, TextEncoder, atob, btoa,
    crypto: {subtle: {
      importKey: (...args) => realCrypto.subtle.importKey(...args),
      encrypt: async (...args) => { encryptCalls++; await pause; return realCrypto.subtle.encrypt(...args); }
    }}, window: {isSecureContext: true, addEventListener: (event, fn) => { windowEvents[event] = fn; }},
    location: {reload: () => { reloads++; }},
    document: {addEventListener: (_, fn) => { ready = fn; },
      getElementById: id => fields[id], createElement: () => ({})}
  });
  vm.runInContext(input.script, context); ready();
  const event = value => ({submitter: {value}, preventDefault: () => {}});
  const pending = submit(event('approve'));
  await submit(event('approve')); // Repeated click must not submit twice.
  if (mode === 'cancel') await submit(event('deny'));
  if (mode === 'leave') windowEvents.pagehide();
  release(); await pending;
  if (fields['handoff-key'].value !== '') throw new Error(mode + ': key not cleared');
  if (mode === 'invalid') {
    if (encryptCalls || !fields['handoff-error'].textContent || fields['approve-button'].disabled)
      throw new Error('invalid key did not recover');
  } else if (encryptCalls !== 1) throw new Error('repeated encryption');
  if (mode === 'success') {
    if (nativeSubmissions !== 1 || !fields['key-handoff'].value) throw new Error('no approval');
  } else if (nativeSubmissions || fields['key-handoff'].value) throw new Error(mode + ': late approval');
  windowEvents.pageshow({persisted: true});
  if (reloads !== 1) throw new Error('history restore did not refresh expired state');
}
(async () => { for (const mode of ['success', 'cancel', 'leave', 'invalid']) await scenario(mode); })()
  .catch(e => { console.error(e.message); process.exit(1); });
"""
        result = subprocess.run(["node", "-e", script], input=json.dumps({
            "script": form.scripts["script"], "data": json.loads(form.scripts["handoff-data"]),
            "key": KEY_B64}), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_tokens_only_login_retains_legacy_api(self):
        config = str(Path(self.tmp.name) / "client.json")
        Path(config).write_text(json.dumps({"server": "https://other.test", "agent": "agent-b", "e2e_key": KEY_B64}))
        connection = self.connection_class()
        harness = self

        class LegacyApproval(connection):
            def request(self, method, path, body=None, headers=None):
                super().request(method, path, body, headers)
                if path == "/oauth/device/code":
                    d = self.result[1]
                    harness.assertNotIn("key_handoff_alg", d)
                    form = harness.consent(d)
                    harness.request("POST", "/oauth/device/authorize", urlencode({
                        "device_code": d["device_code"], "action": "approve",
                        "csrf_token": form.inputs["csrf_token"]["value"]}),
                        headers={"Cookie": "relay_session=test-session-a"})
        with mock.patch("http.client.HTTPSConnection", LegacyApproval), mock.patch.object(auth.time, "sleep"):
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--server", "https://relay.test", "--config", config, "login", "--tokens-only"])
        saved = json.loads(Path(config).read_text())
        self.assertEqual(saved["agent"], "agent-a")
        self.assertNotIn("e2e_key", saved, "legacy login must not mix another relay's key")
        with mock.patch("http.client.HTTPSConnection", LegacyApproval), mock.patch.object(auth.time, "sleep"):
            self.assertEqual(len(auth.device_login("https://relay.test", out=lambda _: None)), 3)


if __name__ == "__main__":
    unittest.main()
