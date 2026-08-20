from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2.errors

from db import get_connection
from config import SHARED_SECRET, AES_MASTER_KEY, PI_PUBLIC_KEYS
from admin_auth import require_admin_key
from audit import log_audit
from utils import (
    calculate_expiry,
    compute_payload_hash,
    compute_payload_hash_from_row,
)
from crypto_paper import derive_session_keys, decrypt_field as decrypt_field_paper
from crypto_modern import derive_tag_key, aes_gcm_decrypt, InvalidTag
from crypto_signing import verify_ed25519_signature

import hmac as hmac_module
import time
import json
import traceback
from datetime import datetime, timezone

app = Flask(__name__, static_folder="../frontend", static_url_path="")


@app.route("/")
def index():
    return app.send_static_file("index.html")


# The frontend is served same-origin by this app (see static_folder below), so no
# blanket CORS is needed. /api/verify/* is scoped open since its responses never
# contain secrets — only sanitized display fields — in case it's ever called from
# a different origin.
CORS(app, resources={r"/api/verify/*": {"origins": "*"}})

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://",
                   default_limits=["200 per hour"])

REPLAY_WINDOW_SECONDS = 30
VALID_CRYPTO_VERSIONS = {"paper_v1", "aes_gcm_v1"}


def verify_request_signature(req) -> bool:
    ts  = req.headers.get("X-Timestamp", "")
    sig = req.headers.get("X-Signature", "")
    if not ts or not sig:
        return False
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    # Reject stale or future-dated requests
    if abs(time.time() - ts_int) > REPLAY_WINDOW_SECONDS:
        return False

    # Use empty dict for GET requests (no body); parse JSON body for POST
    body    = req.get_json(force=True, silent=True) or {}
    payload = ts + json.dumps(body, sort_keys=True, separators=(',', ':'))
    # Ed25519: asymmetric, so verifying this never requires the device's private
    # key -- leaking PI_PUBLIC_KEYS (or this whole server's config) does not let
    # anyone forge a valid signature, unlike the old shared-HMAC-secret scheme.
    return verify_ed25519_signature(payload.encode('utf-8'), sig, PI_PUBLIC_KEYS)


def decrypt_field_for_row(iv_hex, data_hex, crypto_version, tag_uid_hash, key_chars=None):
    """Dispatch to the correct decryption path based on crypto_version."""
    if crypto_version == "aes_gcm_v1":
        key = derive_tag_key(tag_uid_hash, AES_MASTER_KEY)
        return aes_gcm_decrypt(iv_hex, data_hex, key)
    else:
        keys, _ = derive_session_keys(key_chars, SHARED_SECRET)
        return decrypt_field_paper(iv_hex, data_hex, keys)


# ------------------------
# Health Check
# ------------------------
@app.route("/health")
def health():
    return {"status": "ok", "message": "Backend running"}


# ------------------------
# Test DB Connection
# ------------------------
@app.route("/test-db")
def test_db():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "DB connected", "result": result}
    except Exception as e:
        return {"error": str(e)}, 500


# ------------------------
# Add Product (RPi -> Backend)
# ------------------------
@app.route("/api/products", methods=["POST"])
@limiter.limit("30/minute")
def add_product():
    data = request.json or {}
    source_ip = request.remote_addr

    # 1. Signature check - must be first
    if not verify_request_signature(request):
        log_audit(event_type="product_write", result="bad_signature", source_ip=source_ip)
        return jsonify({"error": "Forbidden"}), 403

    # 2. Validate required fields (crypto_version-independent)
    required = ["nonce", "product_id", "batch_id", "mfg_date", "shelf_life",
                "tag_uid", "tag_uid_hash"]
    for f in required:
        if f not in data:
            log_audit(event_type="product_write", result="missing_field",
                       source_ip=source_ip, detail={"field": f})
            return jsonify({"error": f"Missing field: {f}"}), 400

    crypto_version = data.get("crypto_version", "paper_v1")
    if crypto_version not in VALID_CRYPTO_VERSIONS:
        return jsonify({"error": "Invalid crypto_version"}), 400

    key_chars = data.get("key_chars")
    key_chars_str = None

    if crypto_version == "paper_v1":
        if "key_chars" not in data or "key_mac" not in data:
            log_audit(event_type="product_write", result="missing_field",
                       source_ip=source_ip, detail={"field": "key_chars/key_mac"})
            return jsonify({"error": "Missing field: key_chars/key_mac"}), 400
        # 3. Re-derive session keys and verify key_mac (proves caller holds SHARED_SECRET)
        try:
            session_keys, expected_mac = derive_session_keys(data["key_chars"], SHARED_SECRET)
            if not hmac_module.compare_digest(expected_mac, data["key_mac"]):
                log_audit(event_type="product_write", result="bad_key_mac",
                           tag_uid_hash=data.get("tag_uid_hash"), source_ip=source_ip)
                return jsonify({"error": "Invalid key MAC"}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        key_chars_str = json.dumps(data["key_chars"])

    # 4. Decrypt ONLY mfg_date to compute expiry - nothing else is decrypted
    try:
        mfg_plain = decrypt_field_for_row(
            data["mfg_date"]["iv"], data["mfg_date"]["data"],
            crypto_version, data["tag_uid_hash"], key_chars,
        )
        expiry = calculate_expiry(mfg_plain, data["shelf_life"])
    except Exception as e:
        return jsonify({"error": f"mfg_date decrypt failed: {e}"}), 400

    # 5. Payload hash for tamper detection
    payload_hash = compute_payload_hash(data)

    # 6. Write encrypted blobs directly - no plaintext in DB. Nonce is UNIQUE at the
    #    DB level, so a replayed nonce (even under a freshly-forged valid signature)
    #    is rejected here regardless of the 30s timestamp window.
    conn = get_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO products
               (product_id, product_id_iv,
                batch_id,   batch_id_iv,
                mfg_date,   mfg_date_iv,
                tag_uid,    tag_uid_iv,
                shelf_life, expiry_date, payload_hash,
                nonce, key_chars, tag_uid_hash, crypto_version)
               VALUES (%s,%s, %s,%s, %s,%s, %s,%s, %s,%s,%s, %s,%s,%s,%s)""",
            (
                data["product_id"]["data"], data["product_id"]["iv"],
                data["batch_id"]["data"],   data["batch_id"]["iv"],
                data["mfg_date"]["data"],   data["mfg_date"]["iv"],
                data["tag_uid"]["data"],    data["tag_uid"]["iv"],
                data["shelf_life"],
                expiry,
                payload_hash,
                data["nonce"],
                key_chars_str,
                data["tag_uid_hash"],
                crypto_version,
            )
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        log_audit(event_type="product_write", result="duplicate_nonce",
                   tag_uid_hash=data.get("tag_uid_hash"), source_ip=source_ip)
        return jsonify({"error": "Replay detected: nonce already used"}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    log_audit(event_type="product_write", result="success",
               tag_uid_hash=data["tag_uid_hash"], source_ip=source_ip,
               detail={"crypto_version": crypto_version})

    return jsonify({
        "status":      "success",
        "message":     "Product stored",
        "expiry_date": expiry.strftime("%Y-%m-%d"),
    })


# ------------------------
# Consumer Verify (public, rate-limited, no secrets ever returned)
# ------------------------
@app.route("/api/verify/<tag_uid_hash>", methods=["GET"])
@limiter.limit("20/minute")
def verify_tag(tag_uid_hash):
    source_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    conn = get_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT * FROM products
               WHERE tag_uid_hash = %s
               ORDER BY id DESC LIMIT 1""",
            (tag_uid_hash,)
        )
        row = cur.fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    if not row:
        log_audit(event_type="verify_attempt", tag_uid_hash=tag_uid_hash,
                   result="unknown", source_ip=source_ip, user_agent=user_agent)
        return jsonify({"status": "unknown"})

    # row: (id[0], product_id[1], product_id_iv[2], batch_id[3], batch_id_iv[4],
    #       mfg_date[5], mfg_date_iv[6], tag_uid[7], tag_uid_iv[8], shelf_life[9],
    #       expiry_date[10], payload_hash[11], created_at[12], nonce[13],
    #       key_chars[14], tag_uid_hash[15], crypto_version[16])
    stored_hash = row[11]
    live_hash   = compute_payload_hash_from_row(row)
    crypto_version = row[16]
    key_chars = json.loads(row[14]) if row[14] else None

    tampered = (stored_hash != live_hash)
    product_id = batch_id = mfg_date = None

    if not tampered:
        try:
            product_id = decrypt_field_for_row(row[2], row[1], crypto_version, tag_uid_hash, key_chars)
            batch_id   = decrypt_field_for_row(row[4], row[3], crypto_version, tag_uid_hash, key_chars)
            mfg_date   = decrypt_field_for_row(row[6], row[5], crypto_version, tag_uid_hash, key_chars)
        except InvalidTag:
            tampered = True
        except Exception:
            traceback.print_exc()
            tampered = True

    expiry_date = row[10]
    today = datetime.now(timezone.utc).date()
    expired = (not tampered) and (today > expiry_date)

    if tampered:
        status = "tampered"
    elif expired:
        status = "expired"
    else:
        status = "authentic"

    log_audit(event_type="verify_attempt", tag_uid_hash=tag_uid_hash, result=status,
               source_ip=source_ip, user_agent=user_agent)

    response = {
        "status": status,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    if status in ("authentic", "expired"):
        response.update({
            "product_id": product_id,
            "batch_id": batch_id,
            "mfg_date": mfg_date,
            "expiry_date": str(expiry_date),
        })

    return jsonify(response)


# ------------------------
# Admin: List All Products -> returns ENCRYPTED fields
# ------------------------
@app.route("/api/admin/products", methods=["GET"])
@limiter.limit("60/minute")
@require_admin_key
def admin_get_products():
    tag_uid_hash_filter = request.args.get("tag_uid_hash")  # optional
    conn = get_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor()

        if tag_uid_hash_filter:
            cur.execute(
                "SELECT * FROM products WHERE tag_uid_hash = %s ORDER BY id DESC",
                (tag_uid_hash_filter,)
            )
        else:
            cur.execute("SELECT * FROM products ORDER BY id DESC")

        rows = cur.fetchall()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    try:
        products = []
        for row in rows:
            stored_hash = row[11]
            live_hash   = compute_payload_hash_from_row(row)
            tampered    = (stored_hash != live_hash)

            products.append({
                "id":             row[0],
                "product_id":     row[1],   # ciphertext hex
                "product_id_iv":  row[2],
                "batch_id":       row[3],   # ciphertext hex
                "batch_id_iv":    row[4],
                "mfg_date":       row[5],   # ciphertext hex
                "mfg_date_iv":    row[6],
                "tag_uid":        row[7],   # ciphertext hex
                "tag_uid_iv":     row[8],
                "shelf_life":     row[9],
                "expiry_date":    str(row[10]),
                "nonce":          row[13],
                "tag_uid_hash":   row[15],
                "crypto_version": row[16],
                "tampered":       tampered,
                "created_at":     str(row[12]) if row[12] else None,
            })
    except Exception as e:
        print("[ERROR] Processing products list failed:")
        traceback.print_exc()
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

    log_audit(event_type="admin_products_list", result="success",
               source_ip=request.remote_addr, detail={"count": len(products)})

    return jsonify({"status": "success", "count": len(products), "products": products})


# ------------------------
# Admin: Get Keys (debug/legacy - only meaningful for paper_v1 rows)
# ------------------------
@app.route("/api/admin/keys/<tag_uid_hash>", methods=["GET"])
@limiter.limit("10/minute")
@require_admin_key
def admin_get_keys(tag_uid_hash):
    conn = get_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT key_chars, nonce, expiry_date, crypto_version
               FROM products
               WHERE tag_uid_hash = %s
               ORDER BY id DESC LIMIT 1""",
            (tag_uid_hash,)
        )
        row = cur.fetchone()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "Tag not found"}), 404

    log_audit(event_type="admin_key_fetch", tag_uid_hash=tag_uid_hash, result="success",
               source_ip=request.remote_addr)

    try:
        key_chars = json.loads(row[0]) if row[0] else None
        return jsonify({
            "status":         "success",
            "key_chars":      key_chars,
            "nonce":          row[1],
            "expiry_date":    str(row[2]),
            "crypto_version": row[3],
        })
    except Exception as e:
        print("[ERROR] Processing keys failed:")
        traceback.print_exc()
        return jsonify({"error": f"Processing error: {str(e)}"}), 500


# ------------------------
# Run Server
# ------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
