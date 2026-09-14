"""Row signatures. ARCHITECTURE.md §7.4.

This is the single highest-leverage change in the backend, and these tests are
what say so concretely.

v1's payload_hash was an unkeyed SHA-256 over four public ciphertext values: an
attacker with database write access could change the expiry date and simply
recompute it (F13, F15, D12). It was a checksum, not an integrity control.

The property to hold on to: with ROW_SIGNING_KEY held only in the backend's
memory, an adversary with FULL READ/WRITE ACCESS TO THE DATABASE cannot alter any
security-relevant field without the alteration being detected on the next
verification. That is the second of the two claims in §19.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import crypto_rowsig
from crypto_rowsig import ROW_SIG_FIELDS, canonical, sign_row, signable_view, verify_row


def _key(vectors):
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vectors["row_signing_priv_hex"]))


def _pub(vectors):
    return bytes.fromhex(vectors["row_signing_pub_hex"])


def test_matches_the_vector(rowsig_vectors):
    """Canonical JSON and signature are pinned, so a change to either is a
    deliberate act and not an accident."""
    assert canonical(rowsig_vectors["row"]).decode("utf-8") == rowsig_vectors["canonical"]
    assert sign_row(rowsig_vectors["row"], _key(rowsig_vectors)) == rowsig_vectors["signature"]
    assert verify_row(rowsig_vectors["row"], rowsig_vectors["signature"],
                      _pub(rowsig_vectors))


# ================================ THE ADVERSARY WITH DATABASE WRITE ACCESS ====

@pytest.mark.parametrize("field,new_value", [
    ("expiry_date", "2030-01-01"),      # D12, G3 — expired-stock relabelling
    ("status", "withdrawn"),            # G2 — recall evasion, in either direction
    ("crypto_version", "paper_v1"),     # D13, E8 — crypto downgrade
    ("enrol_counter", 0),               # would widen the velocity bound
    ("binding_token_hash", "f" * 64),   # would rebind the record to another tag
    ("shelf_life", 99999),
    ("batch_ref", "SOME-OTHER-BATCH"),
    ("tag_index", "0" * 64),
    ("enc_dek", "00" * 60),
    ("originality_status", "unverified"),
    ("device_id", "00000000-0000-4000-8000-00000000ffff"),
    ("row_key_version", 2),
])
def test_every_security_relevant_field_is_covered(rowsig_vectors, field, new_value):
    """Change one field in the database and the signature stops verifying.

    Each of these is an attack from §16 that v1's recomputable payload_hash left
    wide open.
    """
    tampered = {**rowsig_vectors["row"], field: new_value}
    assert not verify_row(tampered, rowsig_vectors["signature"], _pub(rowsig_vectors))


def test_the_vector_file_documents_the_expiry_tamper(rowsig_vectors):
    tampered = rowsig_vectors["tampered"]["row"]
    assert not verify_row(tampered, rowsig_vectors["signature"], _pub(rowsig_vectors))


def test_signed_field_set_is_complete():
    """A security-relevant column that is NOT in ROW_SIG_FIELDS is unprotected.

    This test does not know which columns matter — it pins the current set, so
    adding a column forces a conscious decision about whether the signature
    should cover it.
    """
    assert set(ROW_SIG_FIELDS) == {
        "tag_index", "binding_token_hash",
        "product_id_ct", "batch_id_ct", "mfg_date_ct", "tag_uid_ct",
        "enc_dek", "shelf_life", "expiry_date", "crypto_version",
        "enrol_counter", "batch_ref", "status", "device_id",
        "originality_status", "enrolled_at", "row_sig_alg", "row_key_version",
    }


# ============================================================== FAIL CLOSED ====

def test_verify_never_raises_on_hostile_input(rowsig_vectors):
    """§15.3 rule 1. Every malformed input is a FAILED verification, not an
    exception that a route might turn into a 500 — or worse, swallow."""
    pub = _pub(rowsig_vectors)
    row = rowsig_vectors["row"]

    assert not verify_row(row, "not-hex", pub)
    assert not verify_row(row, "", pub)
    assert not verify_row(row, None, pub)
    assert not verify_row(row, "aa" * 64, pub)     # right length, wrong signature
    assert not verify_row({}, rowsig_vectors["signature"], pub)
    assert not verify_row({"row_sig_alg": "ed25519"}, rowsig_vectors["signature"], pub)


def test_unknown_signature_algorithm_is_rejected(rowsig_vectors):
    """H1 reserves ed25519+mldsa65 for later. Until it is implemented, anything
    but ed25519 fails — a reserved value must not become an accepted one by
    accident."""
    row = {**rowsig_vectors["row"], "row_sig_alg": "ed25519+mldsa65"}
    assert not verify_row(row, rowsig_vectors["signature"], _pub(rowsig_vectors))
    row = {**rowsig_vectors["row"], "row_sig_alg": "none"}
    assert not verify_row(row, rowsig_vectors["signature"], _pub(rowsig_vectors))


def test_a_different_key_does_not_verify(rowsig_vectors):
    other = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    other_pub = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert not verify_row(rowsig_vectors["row"], rowsig_vectors["signature"], other_pub)


def test_missing_signed_field_raises_on_signing_not_on_verifying():
    """Signing an incomplete row is a programming error and should be loud.
    VERIFYING an incomplete row is an attack and must be quiet and negative."""
    with pytest.raises(crypto_rowsig.RowSigError):
        canonical({"tag_index": "a"})
    assert not verify_row({"tag_index": "a", "row_sig_alg": "ed25519"}, "aa" * 64, b"\x00" * 32)


# ==================================================== CANONICALISATION DRIFT ====

def test_signable_view_normalises_dates_the_same_way_every_time():
    """The classic bug this prevents: a row signs fine at write time with a
    datetime.date, then fails at read time because psycopg2 handed back a
    different type that serialises differently. One projection, used by both."""
    written = {
        **{k: "x" for k in ROW_SIG_FIELDS},
        "row_sig_alg": "ed25519",
        "expiry_date": date(2028, 9, 9),
        "enrolled_at": datetime(2026, 9, 10, 9, 15, tzinfo=timezone.utc),
        "shelf_life": 730,
        "enrol_counter": 3,
        "row_key_version": 1,
    }
    read_back = {**written,
                 "expiry_date": "2028-09-09",
                 "enrolled_at": "2026-09-10T09:15:00+00:00"}

    assert signable_view(written) == signable_view(read_back)

    sk = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    signature = sign_row(signable_view(written), sk)
    assert verify_row(signable_view(read_back), signature, pub)


def test_canonical_json_is_stable_and_sorted(rowsig_vectors):
    """Key order in the source dict must not change the bytes that get signed."""
    row = rowsig_vectors["row"]
    shuffled = dict(reversed(list(row.items())))
    assert canonical(row) == canonical(shuffled)

    parsed = json.loads(canonical(row))
    assert list(parsed) == sorted(parsed)
    assert set(parsed) == set(ROW_SIG_FIELDS)


def test_canonical_json_is_ascii_only(rowsig_vectors):
    """ensure_ascii=True means a product name in Devanagari or a smart quote
    cannot change the byte length of the signed payload depending on the
    serialiser's mood."""
    row = {**rowsig_vectors["row"], "batch_ref": "बैच-२०२६"}
    encoded = canonical(row)
    encoded.decode("ascii")  # raises if any non-ASCII byte slipped through
