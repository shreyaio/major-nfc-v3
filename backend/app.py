from flask import Flask, request, jsonify
from flask_cors import CORS
from db import get_connection
from config import SHARED_SECRET
from utils import (
    calculate_expiry,
    decrypt_field,
    derive_session_keys,
    compute_payload_hash,
    compute_payload_hash_from_row,
)
import hmac as hmac_module
import hashlib
import time
import json
import traceback

app = Flask(__name__)
CORS(app)

REPLAY_WINDOW_SECONDS = 30

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
    expected = hmac_module.new(
        SHARED_SECRET, payload.encode('utf-8'), hashlib.sha256
    ).hexdigest()
    # Constant-time comparison prevents timing attacks
    return hmac_module.compare_digest(expected, sig)


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
# Add Product (RPi → Backend)
# ------------------------
@app.route("/api/products", methods=["POST"])
def add_product():
    data = request.json

    # 1. Signature check — must be first
    if not verify_request_signature(request):
        return jsonify({"error": "Forbidden"}), 403

    # 2. Validate required fields
    required = ["nonce", "key_chars", "key_mac", "product_id", "batch_id",
                "mfg_date", "shelf_life", "tag_uid", "tag_uid_hash"]
    for f in required:
        if f not in data:
            print(f"[DEBUG] Missing field: {f}")
            return jsonify({"error": f"Missing field: {f}"}), 400

    # 3. Re-derive session keys and verify key_mac
    try:
        session_keys, expected_mac = derive_session_keys(
            data["key_chars"], SHARED_SECRET)
        if not hmac_module.compare_digest(expected_mac, data["key_mac"]):
            return jsonify({"error": "Invalid key MAC"}), 403
    except Exception as e:
        print(f"[DEBUG] Session key derivation failed: {e}")
        return jsonify({"error": str(e)}), 400

    # 4. Decrypt ONLY mfg_date to compute expiry — nothing else is decrypted
    try:
        mfg_plain = decrypt_field(
            data["mfg_date"]["iv"], data["mfg_date"]["data"], session_keys)
        expiry = calculate_expiry(mfg_plain, data["shelf_life"])
    except Exception as e:
        print(f"[DEBUG] mfg_date decrypt/expiry failed: {e}")
        return jsonify({"error": f"mfg_date decrypt failed: {e}"}), 400

    # 5. Payload hash for tamper detection
    payload_hash = compute_payload_hash(data)
    key_chars_str = json.dumps(data["key_chars"])

    # 6. Write encrypted blobs directly — no plaintext in DB
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute(
            """INSERT INTO products
               (product_id, product_id_iv,
                batch_id,   batch_id_iv,
                mfg_date,   mfg_date_iv,
                tag_uid,    tag_uid_iv,
                shelf_life, expiry_date, payload_hash,
                nonce, key_chars, tag_uid_hash)
               VALUES (%s,%s, %s,%s, %s,%s, %s,%s, %s,%s,%s, %s,%s,%s)""",
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
            )
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "status":      "success",
        "message":     "Product stored",
        "expiry_date": expiry.strftime("%Y-%m-%d"),
    })


# ------------------------
# Get All Products  →  returns ENCRYPTED fields
# ------------------------
@app.route("/api/products", methods=["GET"])
def get_products():
    tag_uid_hash_filter = request.args.get("tag_uid_hash")  # optional
    try:
        conn = get_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        cur = conn.cursor()
        
        if tag_uid_hash_filter:
            cur.execute(
                "SELECT * FROM products WHERE tag_uid_hash = %s ORDER BY id DESC",
                (tag_uid_hash_filter,)
            )
        else:
            cur.execute("SELECT * FROM products ORDER BY id DESC")
            
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    try:
        products = []
        for row in rows:
            # row index reference:
            # (id[0], product_id[1], product_id_iv[2], batch_id[3], batch_id_iv[4],
            #  mfg_date[5], mfg_date_iv[6], tag_uid[7], tag_uid_iv[8],
            #  shelf_life[9], expiry_date[10], payload_hash[11],
            #  created_at[12], nonce[13], key_chars[14], tag_uid_hash[15])
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
                "tampered":       tampered,
                "created_at":     str(row[12]) if row[12] else None,
            })
    except Exception as e:
        print("[ERROR] Processing products list failed:")
        traceback.print_exc()
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

    return jsonify({"status": "success", "count": len(products), "products": products})


# ------------------------
# Get Keys (Audit/Fallback)
# ------------------------
@app.route("/api/keys/<tag_uid_hash>", methods=["GET"])
def get_keys(tag_uid_hash):
    # 1. Verify HMAC signature — same check as POST /api/products
    if not verify_request_signature(request):
        return jsonify({"error": "Forbidden"}), 403

    # 2. Look up the most recent record for this tag
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute(
            """SELECT key_chars, nonce, expiry_date
               FROM products
               WHERE tag_uid_hash = %s
               ORDER BY id DESC LIMIT 1""",
            (tag_uid_hash,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    try:
        if not row:
            return jsonify({"error": "Tag not found"}), 404

        key_chars = json.loads(row[0])   # parse back from JSON string e.g. ["A","D","Y","X"]

        return jsonify({
            "status":      "success",
            "key_chars":   key_chars,
            "nonce":       row[1],
            "expiry_date": str(row[2]),
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