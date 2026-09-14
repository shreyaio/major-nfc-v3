"""The Pi's signing-key interface. ARCHITECTURE.md §7.5 (decision D2).

File-based now, ATECC608A later. NO CALL SITE EVER TOUCHES RAW KEY BYTES —
enroller.py and drainer.py accept a KeyProvider and nothing else, so swapping in
a secure element later requires zero changes to either.

Selection is via KEY_PROVIDER=file|atecc608a in pi/.env.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@runtime_checkable
class KeyProvider(Protocol):
    def device_id(self) -> str: ...
    def public_key(self) -> bytes: ...            # 32 raw bytes, Ed25519
    def sign(self, message: bytes) -> bytes: ...  # 64 raw bytes


class FileKeyProvider:
    """Reads a hex Ed25519 private key from pi/.env.

    The key is in plaintext on an SD card. This is a KNOWN, ACCEPTED weakness for
    this phase (finding F1). The mitigation is NOT the key store — it is the
    per-batch enrolment quota (§12.6), a database CHECK constraint that bounds
    what a stolen key can do to the remaining quota of one open batch. That
    converts an unlimited compromise into a bounded one, for free.

    Note what this key can and cannot do: it signs enrolment requests. It does
    NOT decrypt anything. In v1 the same box held AES_MASTER_KEY and could
    therefore read the entire register; in v2 the Pi holds only a public
    encryption key (§7.1).
    """

    def __init__(self, privkey_hex: str, device_id: str):
        if not privkey_hex:
            raise ValueError("DEVICE_PRIVATE_KEY is not set in pi/.env")
        try:
            raw = bytes.fromhex(privkey_hex.strip())
        except ValueError as exc:
            raise ValueError("DEVICE_PRIVATE_KEY must be hex") from exc
        if len(raw) != 32:
            raise ValueError(
                f"DEVICE_PRIVATE_KEY must be 32 bytes (64 hex chars), got {len(raw)}")
        if not device_id:
            raise ValueError("DEVICE_ID is not set in pi/.env")
        self._sk = Ed25519PrivateKey.from_private_bytes(raw)
        self._device_id = device_id

    def device_id(self) -> str:
        return self._device_id

    def public_key(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)


class Atecc608aKeyProvider:
    """STUB. Same interface.

    The private key is generated inside the chip over I2C (address 0x60, the same
    bus as the PN532) and never leaves it. Implementing this later requires zero
    changes to enroller.py or drainer.py — that is the entire point of the
    interface.
    """

    def __init__(self, i2c, slot: int = 0):
        raise NotImplementedError(
            "ATECC608A support not built — set KEY_PROVIDER=file and use "
            "FileKeyProvider. See ARCHITECTURE.md §7.5.")

    def device_id(self) -> str:  # pragma: no cover - unreachable stub
        raise NotImplementedError

    def public_key(self) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def sign(self, message: bytes) -> bytes:  # pragma: no cover
        raise NotImplementedError


def load_key_provider(kind: str, *, privkey_hex: str = "", device_id: str = "",
                      i2c=None, slot: int = 0) -> KeyProvider:
    kind = (kind or "file").strip().lower()
    if kind == "file":
        return FileKeyProvider(privkey_hex, device_id)
    if kind == "atecc608a":
        return Atecc608aKeyProvider(i2c, slot)
    raise ValueError(f"KEY_PROVIDER must be 'file' or 'atecc608a', got {kind!r}")
