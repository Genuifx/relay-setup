"""E2EE: AES-256-GCM for relay message bodies.

Wire format: base64(nonce12 || ciphertext || tag16), identical to the
reference implementation in PROTOCOL.md. The server never sees plaintext.
"""
import base64
import json
import os
import time

_KEY_LEN = 32


def load_key(key_b64):
    """Decode a base64url E2EE key, validating length."""
    key = base64.urlsafe_b64decode(key_b64.strip())
    if len(key) != _KEY_LEN:
        raise ValueError("E2EE key must decode to 32 bytes, got %d" % len(key))
    return key


def e2e_encrypt(key_b64, from_id, to_id, type, body):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = load_key(key_b64)
    nonce = os.urandom(12)
    plaintext = json.dumps({"v": 1, "from": from_id, "to": to_id,
                            "type": type, "body": body,
                            "ts": int(time.time())},
                           separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def e2e_decrypt(key_b64, payload_b64):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = load_key(key_b64)
    wire = base64.b64decode(payload_b64)
    nonce, ct = wire[:12], wire[12:]
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(plaintext.decode())
