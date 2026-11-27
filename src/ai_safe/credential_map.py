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
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ai_safe.redaction import PlaceholderRegistry
from ai_safe.security import SecurityError, write_private_file

MAP_FILE = "credential-map.json"
INFRA_MAP_FILE = "infra-map.json"
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
    propagate: str = "expand"
    also_used_as: list[str] = field(default_factory=list)
    kind: str | None = None

    @property
    def is_secret(self) -> bool:
        """Credentials whose presence anywhere is a leak (not usernames,
        emails, identifiers or infrastructure names)."""
        return self.propagate in ("expand", "token")

    def public(self) -> dict:
        return {
            "placeholder": self.placeholder,
            "category": self.category,
            "fingerprint": self.fingerprint,
            "key": self.key,
            "files": self.files,
            "propagate": self.propagate,
            "also_used_as": self.also_used_as,
            "kind": self.kind,
        }


@dataclass
class CredentialMap:
    entries: list[MapEntry] = field(default_factory=list)
    encrypted_values: bool = False

    @classmethod
    def from_registry(cls, registry: PlaceholderRegistry) -> "CredentialMap":
        return cls(
            entries=[
                MapEntry(e.name, e.category.value, e.fingerprint, e.key, sorted(e.files), e.propagate,
                         list(e.also_used_as), e.kind)
                for e in registry.entries()
            ]
        )

    def names(self) -> set[str]:
        return {e.placeholder for e in self.entries}

    def fingerprints(self) -> dict[str, str]:
        """Fingerprints of values that must never appear in the workspace."""
        return {e.fingerprint: e.placeholder for e in self.entries if e.is_secret}

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
            values = {e.name: e.secret for e in registry.entries() if not e.restorable}
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
            entries=[MapEntry(e["placeholder"], e["category"], e["fingerprint"], e.get("key"), list(e.get("files", [])),
                              e.get("propagate", "expand"), list(e.get("also_used_as", [])), e.get("kind"))
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


# ---------------------------------------------------------------------------
# Infrastructure map (restorable)
# ---------------------------------------------------------------------------


@dataclass
class InfraEntry:
    placeholder: str
    token: str      # text in the workspace: ${AI_SAFE_HOST_...} or a pseudonym
    original: str   # text written back on integration
    kind: str


def save_infra_map(state_dir: Path, registry: PlaceholderRegistry, *, mode: str = "placeholder") -> None:
    """Host names, IPs, buckets and cloud IDs are not credentials, so their
    originals may be stored (mode 0600, state directory outside the workspace)
    and written back on integration. Never used to write into the workspace."""
    entries = [{"placeholder": e.name, "token": e.token, "original": e.original, "kind": e.kind}
               for e in registry.entries() if e.restorable and e.files]
    doc = {"version": 1, "mode": mode, "note": "Infrastructure names only - no credentials.", "entries": entries}
    write_private_file(Path(state_dir) / INFRA_MAP_FILE, json.dumps(doc, indent=2))


def load_infra_map(state_dir: Path) -> list[InfraEntry]:
    path = Path(state_dir) / INFRA_MAP_FILE
    if not path.is_file() or path.is_symlink():
        return []
    doc = json.loads(path.read_text())
    return [InfraEntry(e["placeholder"], e["token"], e["original"], e["kind"]) for e in doc.get("entries", [])]


def restore_infra(text: str, entries: list[InfraEntry]) -> str:
    """Replace every infrastructure token by its original (longest token first)."""
    if not entries or not text:
        return text
    by_token = {e.token: e.original for e in entries}
    pattern = re.compile("|".join(re.escape(t) for t in sorted(by_token, key=len, reverse=True)))
    return pattern.sub(lambda m: by_token[m.group(0)], text)
