"""Ephemeral browser-to-CLI key wrapping using RSA-OAEP (SHA-256/MGF1).

The relay only receives the public key and ciphertext. Browser code is still
served by the relay, so this does not remove trust in the deployed web app.
"""
import base64
import json

ALGORITHM = "RSA-OAEP-256"


class KeyReceiver:
    """One login's private key, kept only in memory and never serialized."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        modulus = self._private_key.public_key().public_numbers().n.to_bytes(384, "big")
        self.public_key = {"kty": "RSA", "alg": ALGORITHM,
                           "n": base64.urlsafe_b64encode(modulus).decode().rstrip("="),
                           "e": "AQAB"}

    def unwrap(self, envelope, device_code, client_id):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            if not isinstance(envelope, dict) or set(envelope) != {"alg", "ciphertext", "agent"}:
                raise ValueError()
            if envelope["alg"] != ALGORITHM or not isinstance(envelope["agent"], str) or not envelope["agent"]:
                raise ValueError()
            ciphertext = envelope["ciphertext"]
            if not isinstance(ciphertext, str) or len(ciphertext) != 512:
                raise ValueError()
            ciphertext = base64.b64decode(ciphertext, validate=True)
            if len(ciphertext) != 384:
                raise ValueError()
            label = json.dumps(["relay-e2ee-handoff-v1", device_code, client_id,
                                envelope["agent"]], separators=(",", ":"),
                               ensure_ascii=False).encode()
            key = self._private_key.decrypt(ciphertext, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label))
            if len(key) != 32:
                raise ValueError()
            return base64.urlsafe_b64encode(key).decode(), envelope["agent"]
        except (ValueError, TypeError, KeyError):
            # Never include the envelope, key material, or raw crypto error.
            raise RuntimeError("E2EE key handoff failed; restart login") from None
