"""Proxy routing regression tests; fake connections only, no network."""
import json
import os
from pathlib import Path
import ssl
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk"))
from relay_sdk import auth, client


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def connection(self, module):
        patcher = mock.patch.object(module.http.client, "HTTPSConnection")
        connection = patcher.start()
        self.addCleanup(patcher.stop)
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"ok":true,"agent":"agent-b"}'
        return connection

    def test_oauth_https_proxy_connects_with_verified_tls(self):
        os.environ["HTTPS_PROXY"] = "http://proxy.test:3128"
        connection = self.connection(auth)
        status, data = auth._post_form("https://relay.test", "/oauth/device/code", {"client_id": "relay-cli"})
        self.assertEqual(status, 200)
        self.assertEqual(connection.call_args.args, ("proxy.test", 3128))
        connection.return_value.set_tunnel.assert_called_once_with("relay.test", 443)
        context = connection.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(connection.return_value.request.call_args.args[:2], ("POST", "/oauth/device/code"))

    def test_authenticated_api_uses_proxy_without_token_in_connect(self):
        os.environ["https_proxy"] = "http://proxy.test:8080"
        connection = self.connection(client)
        self.assertEqual(client.RelayClient("https://relay.test:444", "fake-token").me(), "agent-b")
        self.assertEqual(connection.call_args.args, ("proxy.test", 8080))
        connection.return_value.set_tunnel.assert_called_once_with("relay.test", 444)
        self.assertEqual(connection.return_value.request.call_args.kwargs["headers"]["Authorization"], "Bearer fake-token")

    def test_no_proxy_keeps_direct_tls_connection(self):
        os.environ.update(HTTPS_PROXY="http://proxy.test:3128", NO_PROXY="relay.test")
        connection = self.connection(auth)
        auth._post_form("https://relay.test", "/oauth/device/code", {})
        self.assertEqual(connection.call_args.args, ("relay.test", 443))
        connection.return_value.set_tunnel.assert_not_called()

    def test_without_proxy_keeps_direct_connection(self):
        connection = self.connection(client)
        client.RelayClient("https://relay.test", "fake-token").me()
        self.assertEqual(connection.call_args.args, ("relay.test", 443))
        connection.return_value.set_tunnel.assert_not_called()

    def test_unsupported_proxy_fails_closed_without_exposing_credentials(self):
        os.environ["HTTPS_PROXY"] = "socks5://private-user:private-password@proxy.test:1080"
        connection = self.connection(auth)
        with self.assertRaisesRegex(RuntimeError, "Unsupported relay proxy") as raised:
            auth._post_form("https://relay.test", "/oauth/device/code", {})
        self.assertNotIn("private-password", str(raised.exception))
        connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
