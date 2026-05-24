import binascii
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings


def _derive_key() -> bytes:
    settings = get_settings()
    if settings.master_key_hex:
        try:
            key = binascii.unhexlify(settings.master_key_hex.strip())
        except binascii.Error as exc:
            raise ValueError("master_key_hex must be valid hex") from exc
        if len(key) != 32:
            raise ValueError("master_key_hex must decode to exactly 32 bytes for AES-256")
        return key

    return hashlib.sha256(settings.app_secret.encode("utf-8")).digest()


def encrypt_field(plaintext: str) -> bytes:
    key = _derive_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + encrypted


def decrypt_field(ciphertext: bytes) -> str:
    key = _derive_key()
    aesgcm = AESGCM(key)
    nonce, encrypted = ciphertext[:12], ciphertext[12:]
    return aesgcm.decrypt(nonce, encrypted, None).decode("utf-8")
