"""Verified HTTPS, optionally through a standard HTTP CONNECT proxy."""
import http.client
import ssl
from urllib.parse import urlparse
from urllib.request import getproxies, proxy_bypass


def https_connection(target, timeout):
    """Honor HTTPS_PROXY/https_proxy and NO_PROXY without changing TLS trust.

    http.client does not read proxy environment variables itself. Its HTTPS
    CONNECT support still verifies the relay hostname after opening the tunnel.
    Never silently downgrade an unsupported proxy scheme to plaintext.
    """
    host, port = target.hostname, target.port or 443
    authority = target.netloc
    proxy = None if proxy_bypass(authority) else getproxies().get("https")
    context = ssl.create_default_context()
    if not proxy:
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    try:
        endpoint = urlparse(proxy)
        if (endpoint.scheme != "http" or not endpoint.hostname
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment):
            raise ValueError()
        proxy_host, proxy_port = endpoint.hostname, endpoint.port or 80
    except (ValueError, TypeError):
        raise RuntimeError("Unsupported relay proxy; use an HTTP CONNECT proxy without URL credentials") from None
    connection = http.client.HTTPSConnection(
        proxy_host, proxy_port, timeout=timeout, context=context)
    connection.set_tunnel(host, port)
    return connection
