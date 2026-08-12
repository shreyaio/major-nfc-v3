import hmac
import hashlib
import json
import time
import requests
import os
from dotenv import load_dotenv

load_dotenv()
SHARED_SECRET = bytes.fromhex(os.getenv("SHARED_SECRET", ""))
BACKEND_URL = "http://localhost:5000"

def sign_request(body, secret):
    ts = str(int(time.time()))
    payload = ts + json.dumps(body, sort_keys=True, separators=(',', ':'))
    sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return ts, sig

def run_tests():
    print("\n" + "="*40)
    print("SECTION 8 — END-TO-END CHECKLIST")
    print("="*40)

    # 1. GET /health
    try:
        r1 = requests.get(f"{BACKEND_URL}/health")
        print(f"1. GET /health: {'PASSED' if r1.status_code == 200 else 'FAILED'} ({r1.status_code})")
    except: print("1. GET /health: FAILED (Connection Error)")

    # 2. GET /test-db
    try:
        r2 = requests.get(f"{BACKEND_URL}/test-db")
        print(f"2. GET /test-db: {'PASSED' if r2.status_code == 200 else 'FAILED'} ({r2.status_code})")
    except: print("2. GET /test-db: FAILED (Connection Error)")

    # 3. POST /api/products with no headers
    body = {"test": "data"}
    r3 = requests.post(f"{BACKEND_URL}/api/products", json=body)
    print(f"3. POST no headers: {'PASSED' if r3.status_code == 403 else 'FAILED'} ({r3.status_code})")

    # 4. POST with headers but wrong key_mac
    body_bad = {
        "key_chars": ["A","B"],
        "key_mac": "wrong",
        "product_id": {"iv":"0"*20, "data":"0"*20},
        "batch_id": {"iv":"0"*20, "data":"0"*20},
        "mfg_date": {"iv":"0"*20, "data":"0"*20},
        "shelf_life": 365,
        "tag_uid": {"iv":"0"*20, "data":"0"*20}
    }
    ts4, sig4 = sign_request(body_bad, SHARED_SECRET)
    r4 = requests.post(f"{BACKEND_URL}/api/products", json=body_bad, headers={"X-Timestamp":ts4, "X-Signature":sig4})
    print(f"4. POST wrong key_mac: {'PASSED' if r4.status_code == 403 else 'FAILED'} ({r4.json().get('error')})")

    # 5. POST with correct key_mac but timestamp >30s old
    ts5 = str(int(time.time()) - 60)
    payload5 = ts5 + json.dumps(body_bad, sort_keys=True, separators=(',', ':'))
    sig5 = hmac.new(SHARED_SECRET, payload5.encode('utf-8'), hashlib.sha256).hexdigest()
    r5 = requests.post(f"{BACKEND_URL}/api/products", json=body_bad, headers={"X-Timestamp":ts5, "X-Signature":sig5})
    print(f"5. POST stale timestamp: {'PASSED' if r5.status_code == 403 else 'FAILED'} ({r5.status_code})")

if __name__ == "__main__":
    run_tests()
