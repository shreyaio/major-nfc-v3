from datetime import datetime, timedelta
import json as _json
import hashlib

# Paper-cipher functions now live in crypto_paper.py (untouched, byte-identical).
# Re-exported here so existing imports (`from utils import decrypt_field`, etc. in
# the legacy manual test scripts) keep working without changes.
from crypto_paper import (
    derive_session_keys,
    circular_left_shift_bits,
    circular_right_shift_bits,
    invert_bits,
    apply_key_to_block,
    encrypt_paper,
    decrypt_paper,
    decrypt_cbc_paper,
    decrypt_field,
)


def compute_payload_hash(request_body: dict) -> str:
    """Called at write time. Fingerprints the four encrypted blobs."""
    canonical = _json.dumps({
        "product_id": request_body["product_id"]["data"],
        "batch_id":   request_body["batch_id"]["data"],
        "mfg_date":   request_body["mfg_date"]["data"],
        "tag_uid":    request_body["tag_uid"]["data"],
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compute_payload_hash_from_row(row: tuple) -> str:
    """Row index: (id[0], product_id[1], ..., batch_id[3], mfg_date[5], tag_uid[7])"""
    canonical = _json.dumps({
        "product_id": row[1],
        "batch_id":   row[3],
        "mfg_date":   row[5],
        "tag_uid":    row[7],
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def calculate_expiry(mfg_date_str, shelf_life):
    mfg_date = datetime.strptime(mfg_date_str, "%Y-%m-%d")
    return mfg_date + timedelta(days=int(shelf_life))
