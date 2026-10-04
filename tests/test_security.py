"""Security regressions; stdlib only, fake credentials, no network access.

Run from the repository root with:
    python3 -B -m unittest discover -s tests -v

The real HTTP handler is exercised through in-memory sockets. All stores are
redirected to TemporaryDirectory before production modules are imported.
"""
import atexit
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BOOT = tempfile.TemporaryDirectory(prefix="relay-security-import-")
atexit.register(BOOT.cleanup)
os.environ["RELAY_CONF"] = BOOT.name
os.environ["RELAY_DATA"] = BOOT.name
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import relay
import client_example
from relay_sdk import auth, cli, client


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class MemorySocket:
    """Only the socket interface used by BaseHTTPRequestHandler."""

    def __init__(self, request):
        self.request = io.BytesIO(request)
        self.response = bytearray()

    def makefile(self, *args, **kwargs):
        return self.request

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.response.extend(data)


class RelayTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="relay-security-test-")
        self.addCleanup(self.tmp.cleanup)
        self.paths = mock.patch.multiple(
            relay, CONF_DIR=self.tmp.name, DATA_DIR=self.tmp.name,
            TOKENS_PATH=os.path.join(self.tmp.name, "tokens.json"),
            STORE_PATH=os.path.join(self.tmp.name, "messages.jsonl"),
            OAUTH_STORE=os.path.join(self.tmp.name, "oauth.json"),
            SESSIONS_PATH=os.path.join(self.tmp.name, "sessions.json"),
            PASSWORDS_PATH=os.path.join(self.tmp.name, "passwords.json"),
            _sessions={}, _login_attempts={},
            OAUTH_CLIENTS={"relay-cli": "CLI", "other-client": "Other"})
        self.paths.start()
        self.addCleanup(self.paths.stop)
        self.tokens = {"agent-a": "fake-static-agent-a", "agent-b": "fake-static-agent-b"}
        Path(relay.TOKENS_PATH).write_text(json.dumps(
            {digest(token): agent for agent, token in self.tokens.items()}))

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
        raw = (method + " " + path + " HTTP/1.0\r\nHost: relay.test\r\n"
               + "".join(k + ": " + v + "\r\n" for k, v in headers.items())
               + "\r\n").encode() + body
        sock = MemorySocket(raw)
        relay.Handler(sock, ("127.0.0.1", 10000), object())
        self.assertEqual(sock.timeout, relay.Handler.timeout)
        head, payload = bytes(sock.response).split(b"\r\n\r\n", 1)
        status = int(head.split(b" ", 2)[1])
        return status, json.loads(payload) if payload else {}

    def send(self, to, sender="agent-a"):
        status, data = self.request("POST", "/v1/send", {
            "to": to, "type": "note", "payload": "fake-ciphertext"},
            self.tokens[sender])
        self.assertEqual(status, 200)
        return data["id"]

    def inbox_ids(self, agent):
        status, data = self.request("GET", "/v1/inbox", token=self.tokens[agent])
        self.assertEqual(status, 200)
        return [m["id"] for m in data["messages"]]

    def ack(self, agent, ids):
        return self.request("POST", "/v1/ack", {"ids": ids}, self.tokens[agent])

    def refresh(self, token, client_id="relay-cli"):
        return self.request("POST", "/oauth/token", {
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": token})

    def connection_class(self, lose_response=False, fail_first=False):
        harness = self
        attempts = []

        class Connection:
            def __init__(self, host, *args, **kwargs):
                if host != "relay.test":
                    raise AssertionError("Tests must never connect to a real host")

            def request(self, method, path, body=None, headers=None):
                attempts.append(path)
                self.result = harness.request(method, path, body, headers=headers)

            def getresponse(self):
                if lose_response or (fail_first and len(attempts) == 1):
                    raise TimeoutError("simulated response loss after server processing")
                status, data = self.result

                class Response:
                    def read(self):
                        return json.dumps(data).encode()

                response = Response()
                response.status = status
                return response

            def close(self):
                pass

        return Connection


class AckTests(RelayTestCase):
    def test_handler_preserves_upstream_connection_timeout(self):
        self.assertEqual(relay.Handler.timeout, 30)
        self.assertEqual(self.request("GET", "/healthz")[0], 200)

    def test_direct_prune_serializes_message_store_access(self):
        self.send("agent-b")
        real_iter = relay._iter_messages
        observed = []

        def inspect_lock():
            observed.append(relay._lock.locked())
            yield from real_iter()

        with mock.patch.object(relay, "_iter_messages", inspect_lock):
            relay.prune(now=time.time() + relay.MAX_TTL + 1)
        self.assertEqual(observed, [True])
        self.assertEqual(list(relay._iter_messages()), [])

    def test_sender_cannot_delete_another_agents_message(self):
        msg = self.send("agent-b")
        self.assertEqual(self.ack("agent-a", [msg]), (200, {"ok": True, "deleted": 0}))
        self.assertEqual(self.inbox_ids("agent-b"), [msg])

    def test_mixed_ack_only_deletes_owned_messages(self):
        own = self.send("agent-a", "agent-b")
        other = self.send("agent-b")
        self.assertEqual(self.ack("agent-a", [own, other, "missing", own])[1]["deleted"], 1)
        self.assertEqual(self.inbox_ids("agent-a"), [])
        self.assertEqual(self.inbox_ids("agent-b"), [other])
        self.assertEqual(self.ack("agent-a", [own])[1]["deleted"], 0)

    def test_broadcast_ack_is_per_recipient_and_idempotent(self):
        msg = self.send("broadcast")
        self.assertEqual(self.ack("agent-a", [msg])[1]["deleted"], 1)
        self.assertEqual(self.inbox_ids("agent-a"), [])
        self.assertEqual(self.inbox_ids("agent-b"), [msg])
        self.assertEqual(self.ack("agent-a", [msg])[1]["deleted"], 0)
        self.assertEqual(self.ack("agent-b", [msg])[1]["deleted"], 1)
        self.assertEqual(self.inbox_ids("agent-b"), [])

    def test_broadcast_receipts_survive_reload_and_expire_with_message(self):
        msg = self.send("broadcast")
        self.ack("agent-a", [msg])
        self.assertEqual(len(list(relay._iter_messages())), 1)
        self.assertEqual(self.inbox_ids("agent-a"), [])
        self.assertEqual(self.inbox_ids("agent-b"), [msg])
        relay.prune(now=time.time() + relay.MAX_TTL + 1)
        self.assertEqual(list(relay._iter_messages()), [])

    def test_broadcast_internal_receipts_are_not_returned(self):
        msg = self.send("broadcast")
        self.ack("agent-a", [msg])
        status, data = self.request("GET", "/v1/inbox", token=self.tokens["agent-b"])
        self.assertEqual(status, 200)
        self.assertEqual(len(data["messages"]), 1)
        self.assertEqual(set(data["messages"][0]), {"id", "from", "to", "type", "payload", "ts", "exp"})

    def test_ack_requires_authentication(self):
        msg = self.send("agent-b")
        self.assertEqual(self.request("POST", "/v1/ack", {"ids": [msg]})[0], 401)
        self.assertEqual(self.inbox_ids("agent-b"), [msg])

    def test_cookie_auth_uses_same_ack_ownership(self):
        msg = self.send("agent-b")
        relay._sessions["fake-session"] = {"agent": "agent-a", "exp": time.time() + 60}
        status, data = self.request("POST", "/v1/ack", {"ids": [msg]},
                                    headers={"Cookie": "relay_session=fake-session"})
        self.assertEqual((status, data["deleted"]), (200, 0))
        self.assertEqual(self.inbox_ids("agent-b"), [msg])


class OAuthTests(RelayTestCase):
    def test_concurrent_refresh_consumes_old_token_only_once(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        local = threading.local()

        class FirstUnlockBarrier:
            def __enter__(self):
                lock.acquire()

            def __exit__(self, *args):
                lock.release()
                if not getattr(local, "synchronized", False):
                    local.synchronized = True
                    barrier.wait(timeout=5)

        with mock.patch.object(relay, "_lock", FirstUnlockBarrier()):
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs = [pool.submit(self.refresh, refresh) for _ in range(2)]
                results = [job.result(timeout=10) for job in jobs]
        self.assertEqual(sorted(status for status, _ in results), [200, 400])
        successful = next(data for status, data in results if status == 200)
        self.assertEqual(relay.bearer_agent(successful["access_token"]), "agent-a")

    def test_revoke_pruned_access_still_finds_linked_refresh(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        data = relay.load_oauth()
        data["access"].pop(digest(access))
        relay.save_oauth(data)
        self.request("POST", "/oauth/revoke", {"token": access}, self.tokens["agent-a"])
        self.assertEqual(self.refresh(refresh)[1].get("error"), "invalid_grant")

    def test_inconsistent_refresh_link_cannot_revoke_another_client(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        other_access, other_refresh = relay.issue_token_pair("agent-a", "other-client", "relay")
        data = relay.load_oauth()
        data["refresh"][digest(refresh)]["access_hash"] = digest(other_access)
        relay.save_oauth(data)
        self.request("POST", "/oauth/revoke", {"token": refresh}, access)
        self.assertEqual(relay.bearer_agent(other_access), "agent-a")
        self.assertEqual(self.refresh(other_refresh, "other-client")[0], 200)

    def test_revoking_access_also_revokes_linked_refresh(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        self.assertEqual(self.request("POST", "/oauth/revoke", {"token": access}, access)[0], 200)
        self.assertIsNone(relay.bearer_agent(access))
        self.assertEqual(self.refresh(refresh)[1].get("error"), "invalid_grant")

    def test_revoking_refresh_also_revokes_linked_access(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        self.assertEqual(self.request("POST", "/oauth/revoke", {"token": refresh}, access)[0], 200)
        self.assertIsNone(relay.bearer_agent(access))
        self.assertEqual(self.refresh(refresh)[1].get("error"), "invalid_grant")

    def test_revocation_preserves_other_clients_and_agents(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        other_access, other_refresh = relay.issue_token_pair("agent-a", "other-client", "relay")
        b_access, b_refresh = relay.issue_token_pair("agent-b", "relay-cli", "relay")
        self.request("POST", "/oauth/revoke", {"token": access}, access)
        self.assertEqual(relay.bearer_agent(other_access), "agent-a")
        self.assertEqual(relay.bearer_agent(b_access), "agent-b")
        self.assertEqual(self.refresh(other_refresh, "other-client")[0], 200)
        self.assertEqual(self.refresh(b_refresh)[0], 200)

    def test_cannot_revoke_another_agents_pair(self):
        access, refresh = relay.issue_token_pair("agent-b", "relay-cli", "relay")
        self.request("POST", "/oauth/revoke", {"token": refresh}, self.tokens["agent-a"])
        self.assertEqual(relay.bearer_agent(access), "agent-b")
        self.assertEqual(self.refresh(refresh)[0], 200)

    def test_revocation_still_requires_authentication(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        self.assertEqual(self.request("POST", "/oauth/revoke", {"token": refresh})[0], 401)
        self.assertEqual(relay.bearer_agent(access), "agent-a")

    def test_refresh_must_match_issuing_client(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        self.assertEqual(self.refresh(refresh, "other-client")[1].get("error"), "invalid_grant")
        self.assertEqual(relay.bearer_agent(access), "agent-a")
        self.assertEqual(self.refresh(refresh)[0], 200)

    def test_refresh_rotation_invalidates_old_pair(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        status, result = self.refresh(refresh)
        self.assertEqual(status, 200)
        self.assertIsNone(relay.bearer_agent(access))
        self.assertEqual(self.refresh(refresh)[1].get("error"), "invalid_grant")
        self.assertEqual(relay.bearer_agent(result["access_token"]), "agent-a")

    def test_device_code_must_match_issuing_client(self):
        data = relay.load_oauth()
        data["device"]["fake-device-code"] = {
            "agent": "agent-a", "client_id": "relay-cli", "scope": "relay",
            "status": "approved", "exp": time.time() + 60, "last_poll": 0}
        relay.save_oauth(data)
        params = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                  "device_code": "fake-device-code", "client_id": "other-client"}
        self.assertEqual(self.request("POST", "/oauth/token", params)[1].get("error"), "invalid_grant")
        params["client_id"] = "relay-cli"
        self.assertEqual(self.request("POST", "/oauth/token", params)[0], 200)

    def test_logout_with_expired_access_revokes_refresh_and_preserves_key(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        data = relay.load_oauth()
        data["access"][digest(access)]["exp"] = time.time() - 1
        relay.save_oauth(data)
        config = os.path.join(self.tmp.name, "config.json")
        Path(config).write_text(json.dumps({
            "server": "http://relay.test", "access_token": access,
            "refresh_token": refresh, "access_expires_at": time.time() - 1,
            "e2e_key": "fake-key-not-used"}))
        with mock.patch("http.client.HTTPConnection", self.connection_class()):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["--config", config, "logout"])
        self.assertEqual(relay.load_oauth()["refresh"], {})
        self.assertEqual(relay.load_oauth()["access"], {})
        self.assertEqual(json.loads(Path(config).read_text())["e2e_key"], "fake-key-not-used")
        self.assertNotIn("refresh_token", json.loads(Path(config).read_text()))

    def test_logout_reports_failure_if_remote_revocation_is_unconfirmed(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        config = os.path.join(self.tmp.name, "config.json")
        Path(config).write_text(json.dumps({
            "server": "http://relay.test", "access_token": access,
            "refresh_token": refresh, "access_expires_at": time.time() + 600}))
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("http.client.HTTPConnection", side_effect=OSError("offline")):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as result:
                    cli.main(["--config", config, "logout"])
        self.assertEqual(result.exception.code, 1)
        self.assertNotIn("服务端令牌已吊销", output.getvalue())
        self.assertIn("not confirmed", errors.getvalue())
        self.assertNotIn("refresh_token", json.loads(Path(config).read_text()))
        self.assertEqual(self.refresh(refresh)[0], 200)

    def test_logout_with_missing_server_cannot_claim_revocation(self):
        config = os.path.join(self.tmp.name, "config.json")
        Path(config).write_text(json.dumps({"refresh_token": "fake-refresh"}))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                cli.main(["--config", config, "logout"])
        self.assertEqual(result.exception.code, 1)
        self.assertNotIn("refresh_token", json.loads(Path(config).read_text()))

    def test_truncated_refresh_response_still_clears_local_logout_tokens(self):
        access, refresh = relay.issue_token_pair("agent-a", "relay-cli", "relay")
        config = os.path.join(self.tmp.name, "config.json")
        Path(config).write_text(json.dumps({
            "server": "http://relay.test", "access_token": access,
            "refresh_token": refresh, "access_expires_at": 0}))
        connection = self.connection_class()

        class TruncatedResponse(connection):
            def getresponse(self):
                raise http.client.IncompleteRead(b"partial", 100)

        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("http.client.HTTPConnection", TruncatedResponse):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as result:
                    cli.main(["--config", config, "logout"])
        self.assertEqual(result.exception.code, 1)
        self.assertIn("not confirmed", errors.getvalue())
        self.assertNotIn("access_token", json.loads(Path(config).read_text()))
        self.assertNotIn("refresh_token", json.loads(Path(config).read_text()))
        # The ambiguous refresh succeeded once server-side, so report uncertainty.
        self.assertEqual(len(relay.load_oauth()["refresh"]), 1)
        self.assertNotIn(digest(refresh), relay.load_oauth()["refresh"])


class TokenStoreTests(RelayTestCase):
    def test_temporary_config_is_private_before_writing_any_secret(self):
        config = os.path.join(self.tmp.name, "config.json")
        store = auth.TokenStore(config)
        store.data = {"access_token": "fake-access", "e2e_key": "fake-key"}
        real_dump = json.dump
        modes = []

        def inspect_before_write(data, stream, *args, **kwargs):
            modes.append(stat.S_IMODE(os.fstat(stream.fileno()).st_mode))
            return real_dump(data, stream, *args, **kwargs)

        old_umask = os.umask(0)
        try:
            with mock.patch.object(auth.json, "dump", inspect_before_write):
                store.save()
        finally:
            os.umask(old_umask)
        self.assertEqual(modes, [0o600])
        self.assertEqual(stat.S_IMODE(os.stat(config).st_mode), 0o600)
        self.assertEqual(json.loads(Path(config).read_text()), store.data)

    def test_predictable_temporary_symlink_is_not_followed(self):
        config = os.path.join(self.tmp.name, "config.json")
        victim = Path(self.tmp.name) / "unrelated.txt"
        victim.write_text("untouched")
        os.symlink(victim, config + ".tmp")
        store = auth.TokenStore(config)
        store.data = {"access_token": "fake-access"}
        store.save()
        self.assertEqual(victim.read_text(), "untouched")
        self.assertEqual(json.loads(Path(config).read_text()), store.data)

    def test_failed_save_keeps_original_and_cleans_temporary_file(self):
        config = os.path.join(self.tmp.name, "config.json")
        Path(config).write_text('{"old": true}')
        store = auth.TokenStore(config)
        store.data = {"unserializable": object()}
        before = set(Path(self.tmp.name).iterdir())
        with self.assertRaises(TypeError):
            store.save()
        self.assertEqual(json.loads(Path(config).read_text()), {"old": True})
        self.assertEqual(set(Path(self.tmp.name).iterdir()), before)


class RetryTests(RelayTestCase):
    def test_sdk_does_not_duplicate_send_when_response_is_lost(self):
        sender = client.RelayClient("http://relay.test", self.tokens["agent-a"])
        with mock.patch("http.client.HTTPConnection", self.connection_class(lose_response=True)):
            with mock.patch.object(client.time, "sleep"):
                with self.assertRaises(client.RelayError) as error:
                    sender.send("agent-b", "note", "fake-ciphertext")
        self.assertEqual(len(self.inbox_ids("agent-b")), 1)
        self.assertIn("may have been accepted", str(error.exception))

    def test_reference_does_not_duplicate_send_when_response_is_lost(self):
        sender = client_example.RelayClient("http://relay.test", self.tokens["agent-a"], "agent-a")
        connection = self.connection_class(lose_response=True)
        with mock.patch.object(sender, "_connect", lambda: connection("relay.test")):
            with mock.patch.object(client_example.time, "sleep"):
                with self.assertRaises(RuntimeError) as error:
                    sender.send("agent-b", "note", "fake-ciphertext")
        self.assertEqual(len(self.inbox_ids("agent-b")), 1)
        self.assertIn("may have been accepted", str(error.exception))

    def test_sdk_still_retries_read_only_requests(self):
        sender = client.RelayClient("http://relay.test", self.tokens["agent-a"])
        with mock.patch("http.client.HTTPConnection", self.connection_class(fail_first=True)):
            with mock.patch.object(client.time, "sleep"):
                self.assertEqual(sender.me(), "agent-a")


if __name__ == "__main__":
    unittest.main()
