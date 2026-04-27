"""
core/vault.py — Cifrado AES para el vault de credenciales
Usa AES-256-GCM via cryptography library.
VAULT_KEY se lee de la variable de entorno — nunca se persiste.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── Clave del vault ───────────────────────────────────────────
_VAULT_KEY_RAW = os.environ.get("VAULT_KEY", "")
_SALT = b"hackeadora_vault_v1"   # salt fijo — la seguridad viene de VAULT_KEY

def _derive_key(raw_key: str) -> bytes:
    """Deriva una clave AES-256 desde VAULT_KEY usando PBKDF2."""
    if not raw_key:
        raise ValueError(
            "VAULT_KEY no configurada. Añade VAULT_KEY=<clave-segura> al .env"
        )
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=100_000,
    )
    return kdf.derive(raw_key.encode())

def encrypt(plaintext: str) -> str:
    """Cifra un string con AES-256-GCM. Devuelve base64."""
    key = _derive_key(_VAULT_KEY_RAW)
    nonce = os.urandom(12)   # 96 bits — recomendado para GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # nonce + ciphertext en base64
    return base64.b64encode(nonce + ct).decode()

def decrypt(ciphertext_b64: str) -> str:
    """Descifra un string cifrado con encrypt(). Devuelve plaintext."""
    key = _derive_key(_VAULT_KEY_RAW)
    data = base64.b64decode(ciphertext_b64)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

def mask(value: str) -> str:
    """Enmascara un valor para mostrarlo en logs/UI."""
    if not value or len(value) < 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
