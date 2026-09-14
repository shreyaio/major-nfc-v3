#!/usr/bin/env python3
"""Regenerate the cross-device test vectors. ARCHITECTURE.md §15.3 rule 7, §17.2.

    python backend/scripts/gen_vectors.py

The Pi and the backend share three canonicalisation rules — UID normalisation,
envelope sealing, and the request-signing payload — and they are implemented
TWICE, on purpose, because the two deployables ship to different machines and
neither may import the other.

A drift between the two copies is invisible until production: tags enrol fine,
and then every one of them verifies as UNKNOWN because the two sides compute
different indexes. So the drift is made a BUILD-TIME FAILURE instead. These
vectors are the pin, and tests/unit/test_cross_device.py runs both
implementations against them in CI.

Regenerate only when you deliberately change a canonicalisation rule — and if
you do, understand that every tag already in the field was written under the old
one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
VECTORS = BACKEND / "tests" / "vectors"

sys.path.insert(0, str(BACKEND))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

import crypto_envelope  # noqa: E402
import crypto_rowsig  # noqa: E402
import crypto_signing  # noqa: E402
import tag_index  # noqa: E402

# Fixed, non-secret test key material. These are TEST VECTORS: the keys are
# deliberately trivial and must never be used for anything real.
FIELD_PRIV = bytes(range(32))
ROW_PRIV = bytes(range(32, 64))
TAG_INDEX_KEY = bytes([0xA5]) * 32
DEK = bytes([0x11]) * 32
NONCES = {
    "batch_id": bytes([0x21]) * 12,
    "mfg_date": bytes([0x22]) * 12,
    "product_id": bytes([0x23]) * 12,
    "tag_uid": bytes([0x24]) * 12,
}
WRAP_NONCE = bytes([0x31]) * 12
EPHEMERAL_PRIV = bytes([0x42]) * 32


def uid_vectors() -> dict:
    valid = [
        {"input": "04A1B2C3D4E5F6", "normalised": "04A1B2C3D4E5F6"},
        {"input": "04a1b2c3d4e5f6", "normalised": "04A1B2C3D4E5F6"},
        {"input": "04:a1:b2:c3:d4:e5:f6", "normalised": "04A1B2C3D4E5F6"},
        {"input": "04-A1-B2-C3-D4-E5-F6", "normalised": "04A1B2C3D4E5F6"},
        {"input": " 04 A1 B2 C3 D4 E5 F6 ", "normalised": "04A1B2C3D4E5F6"},
    ]
    for case in valid:
        case["tag_index"] = tag_index.tag_index(case["input"], TAG_INDEX_KEY)

    return {
        "_note": "UID normalisation must be IDENTICAL on the Pi and the backend. "
                 "A drift here makes every genuine tag read as UNKNOWN.",
        "tag_index_key_hex": TAG_INDEX_KEY.hex(),
        "valid": valid,
        "invalid": [
            {"input": "04A1B2C3D4E5", "why": "too short — 12 hex chars, not 14"},
            {"input": "04A1B2C3D4E5F6AA", "why": "too long"},
            {"input": "04A1B2C3D4E5G6", "why": "G is not hex"},
            {"input": "04A1B2C3D4E5F", "why": "13 hex chars"},
            {"input": "", "why": "empty"},
        ],
    }


def mirror_vectors() -> dict:
    return {
        "_note": "The m parameter parser. Hostile inputs are 400s, not verdicts.",
        "valid": [
            {"m": "04A1B2C3D4E5F6x0001A7", "uid": "04A1B2C3D4E5F6",
             "counter": 0x0001A7, "placeholder": False},
            {"m": "04a1b2c3d4e5f6x0001a7", "uid": "04A1B2C3D4E5F6",
             "counter": 0x0001A7, "placeholder": False,
             "why": "lowercase is uppercased before matching"},
            {"m": "00000000000000x000000", "uid": "00000000000000",
             "counter": 0, "placeholder": True,
             "why": "B7 — the mirror was never enabled; MIRROR_DISABLED, never UNKNOWN"},
            {"m": "04A1B2C3D4E5F6xFFFFFF", "uid": "04A1B2C3D4E5F6",
             "counter": 0xFFFFFF, "placeholder": False,
             "why": "the 24-bit counter maximum"},
            {"m": "０４A1B2C3D4E5F6x0001A7", "uid": "04A1B2C3D4E5F6",
             "counter": 0x0001A7, "placeholder": False,
             "why": "B5 — full-width digits NFKC-normalise to ASCII and are then "
                    "ACCEPTED. The security property is not that they are "
                    "rejected; it is that the edge and the origin independently "
                    "reach the SAME canonical value, so nothing can be smuggled "
                    "past one parser and read differently by the other."},
        ],
        "invalid": [
            {"m": "04A1B2C3D4E5F60001A7", "why": "B3 — no separator"},
            {"m": "04A1B2C3D4E5F6X0001A7extra", "why": "B3 — trailing data"},
            {"m": "04A1B2C3D4E5F6x0001A", "why": "B3 — 5-digit counter"},
            {"m": "04A1B2C3D4E5F6x0001A7" + "A" * 60, "why": "B4 — over the 64-char cap"},
            {"m": "'; DROP TABLE products;--", "why": "B3 — not that it could work, but it is a 400"},
        ],
        "tokens": {
            "valid": ["9F3C" + "0" * 28, "A" * 32],
            "invalid": [
                {"t": "", "why": "B6 — t is mandatory, there is no UID-only path"},
                {"t": "A" * 31, "why": "too short"},
                {"t": "A" * 33, "why": "too long"},
                {"t": "G" * 32, "why": "not hex"},
            ],
        },
    }


def envelope_vectors() -> dict:
    field_pub = X25519PrivateKey.from_private_bytes(FIELD_PRIV).public_key(
    ).public_bytes(Encoding.Raw, PublicFormat.Raw)
    fields = {
        "product_id": "AMOX-500-0001",
        "batch_id": "AMX-2026-09-001",
        "mfg_date": "2026-09-10",
        "tag_uid": "04A1B2C3D4E5F6",
    }
    sealed = crypto_envelope._seal_record(
        fields, field_pub, dek=DEK, nonces=NONCES,
        esk=X25519PrivateKey.from_private_bytes(EPHEMERAL_PRIV),
        wrap_nonce=WRAP_NONCE)

    return {
        "_note": "Both pi/crypto_envelope.py and backend/crypto_envelope.py must "
                 "produce EXACTLY this output from these inputs, and both must "
                 "open it back to the same plaintext. AAD binds each ciphertext "
                 "to its field name, which is what stops D11 at the primitive "
                 "level.",
        "field_recipient_priv_hex": FIELD_PRIV.hex(),
        "field_recipient_pub_hex": field_pub.hex(),
        "dek_hex": DEK.hex(),
        "ephemeral_priv_hex": EPHEMERAL_PRIV.hex(),
        "wrap_nonce_hex": WRAP_NONCE.hex(),
        "nonces_hex": {k: v.hex() for k, v in NONCES.items()},
        "plaintext": fields,
        "sealed": sealed,
    }


def rowsig_vectors() -> dict:
    row = {
        "tag_index": "b" * 64,
        "binding_token_hash": "c" * 64,
        "product_id_ct": '{"c":"aabb","n":"112233"}',
        "batch_id_ct": '{"c":"ccdd","n":"445566"}',
        "mfg_date_ct": '{"c":"eeff","n":"778899"}',
        "tag_uid_ct": '{"c":"0011","n":"aabbcc"}',
        "enc_dek": "dd" * 60,
        "shelf_life": 730,
        "expiry_date": "2028-09-09",
        "crypto_version": "aes_gcm_v2",
        "enrol_counter": 3,
        "batch_ref": "AMX-2026-09-001",
        "status": "active",
        "device_id": "00000000-0000-4000-8000-000000000001",
        "originality_status": "verified",
        "enrolled_at": "2026-09-10T09:15:00+00:00",
        "row_sig_alg": "ed25519",
        "row_key_version": 1,
    }
    sk = Ed25519PrivateKey.from_private_bytes(ROW_PRIV)
    return {
        "_note": "The canonical JSON and the signature over it. expiry_date, "
                 "status, crypto_version and enrol_counter are INSIDE this "
                 "signature — that is what stops an attacker with full database "
                 "write access from changing any of them undetected (D12, D13).",
        "row_signing_priv_hex": ROW_PRIV.hex(),
        "row_signing_pub_hex": sk.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex(),
        "row": row,
        "canonical": crypto_rowsig.canonical(row).decode("utf-8"),
        "signature": crypto_rowsig.sign_row(row, sk),
        "tampered": {
            "_why": "Only expiry_date differs. The signature must NOT verify.",
            "row": {**row, "expiry_date": "2030-01-01"},
        },
    }


def reqsig_vectors() -> dict:
    body = b'{"schema":"nfcmed.enrol.v2"}'
    sk = Ed25519PrivateKey.from_private_bytes(ROW_PRIV)
    timestamp = "1789000000"
    idem = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    payload = crypto_signing.build_signed_payload("ed25519", timestamp, idem, body)
    return {
        "_note": "The request-signing payload, built identically by "
                 "backend/crypto_signing.py and pi/drainer.py. It hashes the RAW "
                 "body bytes rather than re-serialising parsed JSON, which "
                 "removes a whole class of canonicalisation mismatch — and it "
                 "lets the signature be checked BEFORE anything parses the body.",
        "device_priv_hex": ROW_PRIV.hex(),
        "device_pub_hex": sk.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex(),
        "alg": "ed25519",
        "timestamp": timestamp,
        "idempotency_key": idem,
        "raw_body_utf8": body.decode("ascii"),
        "signed_payload_utf8": payload.decode("ascii"),
        "signature": sk.sign(payload).hex(),
    }


def counter_vectors() -> dict:
    return {
        "_note": "CNT_BYTE_ORDER CALIBRATION RESULT. This file is a PLACEHOLDER "
                 "until step §20.7 has actually been run on a scrap tag. Do not "
                 "guess the value: the Pi and the backend both refuse to start "
                 "without it, because a wrong byte order makes every "
                 "enrol_counter wrong and every velocity bound nonsense — "
                 "silently.",
        "calibrated": False,
        "cnt_byte_order": None,
        "procedure": [
            "Enable the counter and mirror on a scrap tag.",
            "READ_CNT (39h 02h) -> record the 3 raw bytes.",
            "Read the NDEF and extract the 6 mirrored hex chars after the 'x'.",
            "Whichever interpretation matches is the answer.",
            "Record it in pi/.env AND backend/.env, and fill in this file.",
        ],
        "observation": {"read_cnt_raw_hex": None, "mirrored_hex": None},
        "interpretations": {
            "msb": "int.from_bytes(raw, 'big')",
            "lsb": "int.from_bytes(raw, 'little')",
        },
    }


def main() -> int:
    VECTORS.mkdir(parents=True, exist_ok=True)
    written = {
        "uid.json": uid_vectors(),
        "mirror.json": mirror_vectors(),
        "envelope.json": envelope_vectors(),
        "rowsig.json": rowsig_vectors(),
        "reqsig.json": reqsig_vectors(),
    }
    for name, content in written.items():
        (VECTORS / name).write_text(json.dumps(content, indent=2) + "\n",
                                    encoding="utf-8")
        print(f"wrote tests/vectors/{name}")

    # counter.json is NOT regenerated if it already carries a real calibration —
    # that value comes from hardware, not from this script.
    counter_path = VECTORS / "counter.json"
    if not counter_path.exists():
        counter_path.write_text(json.dumps(counter_vectors(), indent=2) + "\n",
                                encoding="utf-8")
        print("wrote tests/vectors/counter.json (placeholder — run §20.7)")
    else:
        existing = json.loads(counter_path.read_text(encoding="utf-8"))
        state = "calibrated" if existing.get("calibrated") else "still a placeholder"
        print(f"kept  tests/vectors/counter.json ({state})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
