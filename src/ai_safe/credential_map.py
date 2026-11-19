"""Credential mapping (placeholder <-> original credential).

Stored in the session state directory, *outside* the AI workspace, with 0600
permissions inside a 0700 directory.

* ``credential-map.json`` - placeholder name, category, keyed fingerprint,
  key name and file list. **Never contains secret values.** This is all that
  verification, review and integration need.
* ``credential-secrets.enc`` - optional (``security.store_secret_values``):
  original values encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a
  key derived from a passphrase with scrypt. Not needed for normal integration;
  ai-safe never writes these values into the AI workspace.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ai_safe.redaction import PlaceholderRegistry
from ai_safe.security import SecurityError, write_private_file

MAP_FILE = "credential-map.json"
SECRETS_FILE = "credential-secrets.enc"
PASSPHRASE_ENV = "AI_SAFE_MAPPING_PASSPHRASE"
_SCRYPT_N = 2**15


@dataclass
class MapEntry:
    placeholder: str
    category: str
    fingerprint: str
    key: str | None
    files: list[str] = field(default_factory=list)

    def public(self) -> dict:
        return {
            "placeholder": self.placeholder,
            "category": self.category,
            "fingerprint": self.fingerprint,
            "key": self.key,
            "files": self.files,
        }


@dataclass
class CredentialMap:
    entries: list[MapEntry] = field(default_factory=list)
    encrypted_values: bool = False

    @classmethod
    def from_registry(cls, registry: PlaceholderRegistry) -> "CredentialMap":
        return cls(
            entries=[
                MapEntry(e.name, e.category.value, e.fingerprint, e.key, sorted(e.files))
                for e in registry.entries()
            ]
        )

    def names(self) -> set[str]:
        return {e.placeholder for e in self.entries}

    def fingerprints(self) -> dict[str, str]:
        return {e.fingerprint: e.placeholder for e in self.entries}

    def env_template(self) -> str:
        lines = ["# Placeholders used in the AI workspace. Provide real values via your",
                 "# environment or secret manager - never commit them."]
        lines += [f"{e.placeholder}=" for e in self.entries]
        return "\n".join(lines) + "\n"

    # -- persistence --------------------------------------------------------

    def save(self, state_dir: Path, registry: PlaceholderRegistry | None = None, *,
             store_secret_values: bool = False, passphrase: str | None = None) -> None:
        state_dir = Path(state_dir)
        if store_secret_values:
            if registry is None:
                raise SecurityError("cannot store secret values without the registry")
            if not passphrase:
                raise SecurityError(
                    f"security.store_secret_values=true requires a passphrase (set {PASSPHRASE_ENV} or enter it when prompted)"
                )
            values = {e.name: e.secret for e in registry.entries()}
            write_private_file(state_dir / SECRETS_FILE, _encrypt(json.dumps(values).encode(), passphrase))
            self.encrypted_values = True
        doc = {
            "version": 1,
            "note": "No secret values are stored in this file.",
            "encrypted_values": self.encrypted_values,
            "entries": [e.public() for e in self.entries],
        }
        write_private_file(state_dir / MAP_FILE, json.dumps(doc, indent=2))

    @classmethod
    def load(cls, state_dir: Path) -> "CredentialMap":
        path = Path(state_dir) / MAP_FILE
        if not path.exists():
            return cls()
        doc = json.loads(path.read_text())
        return cls(
            entries=[MapEntry(e["placeholder"], e["category"], e["fingerprint"], e.get("key"), list(e.get("files", [])))
                     for e in doc.get("entries", [])],
            encrypted_values=bool(doc.get("encrypted_values")),
        )

    @staticmethod
    def load_secret_values(state_dir: Path, passphrase: str) -> dict[str, str]:
        """Decrypt stored values. For the developer only; never used to write
        into the AI workspace or into AI-generated files."""
        path = Path(state_dir) / SECRETS_FILE
        if not path.exists():
            raise SecurityError("no encrypted credential values stored for this session")
        return json.loads(_decrypt(path.read_bytes(), passphrase))


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _encrypt(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    token = Fernet(_derive(passphrase, salt)).encrypt(data)
    return json.dumps({"v": 1, "kdf": "scrypt", "n": _SCRYPT_N, "salt": base64.b64encode(salt).decode(), "token": token.decode()}).encode()


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    doc = json.loads(blob)
    salt = base64.b64decode(doc["salt"])
    try:
        return Fernet(_derive(passphrase, salt)).decrypt(doc["token"].encode())
    except InvalidToken:
        raise SecurityError("wrong passphrase or corrupted mapping") from None
