"""relay_sdk -- SDK for the agent message relay.

Submodules:
  crypto  AES-256-GCM end-to-end encryption of message bodies
  client  HTTPS JSON API client (Bearer auth, inbox, send, ack)
  auth    OAuth 2.0 Device Authorization Grant (RFC 8628) + token store
  cli     `relay-cli` command line interface
"""
from .crypto import e2e_encrypt, e2e_decrypt
from .client import RelayClient
from .auth import TokenStore, device_login, get_valid_token

__all__ = ["e2e_encrypt", "e2e_decrypt", "RelayClient",
           "TokenStore", "device_login", "get_valid_token"]
__version__ = "0.1.0"
