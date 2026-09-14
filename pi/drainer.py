"""Background sender for the durable outbox. ARCHITECTURE.md §12.3, §12.4.

Polls the outbox, signs each payload with the device's KeyProvider, POSTs it to
/api/v2/enrol, and retries until the server returns 2xx.

THE TERMINAL/RETRYABLE SPLIT IS THE PART TO GET RIGHT (§10.2):

  terminal  400, 403, 409, 413, 415 -> mark failed, alert the operator
  retryable 429, 5xx, any network error -> back off and try again, forever

Getting this split wrong is how an outbox either spins forever on a permanently
bad record or silently drops a good one.

One special case, and it is easy to miss: `409 tag_already_enrolled` arriving
for a request whose idempotency key we have already sent is a SUCCESS, not a
failure — it means our earlier attempt landed and we never saw the response. The
backend replays the stored response for a known idempotency key, so a true
duplicate returns 200; a 409 with tag_already_enrolled after at least one
attempt means the same tag was enrolled under a different key, which is an
operator problem worth flagging.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid

import requests

log = logging.getLogger(__name__)

REQ_SIG_DOMAIN = b"nfcmed/v2/req:"
SIG_ALG = "ed25519"

# Mirrors backend/errors.py::TERMINAL_STATUSES. The two lists must agree; they
# are in different deployables, so a test vector cannot pin them — this comment
# and the §10.2 table are what keep them together.
TERMINAL_STATUSES = frozenset({400, 403, 409, 413, 415})

POLL_INTERVAL = 2.0
REQUEST_TIMEOUT = 30


def build_signed_payload(alg: str, timestamp: str, idempotency_key: str,
                         raw_body: bytes) -> bytes:
    """MUST produce identical bytes to backend/crypto_signing.build_signed_payload.
    Pinned by backend/tests/vectors/reqsig.json, which both sides run against."""
    body_hash = hashlib.sha256(raw_body).hexdigest()
    return (REQ_SIG_DOMAIN + alg.encode("ascii") + b"\n"
            + timestamp.encode("ascii") + b"\n"
            + idempotency_key.encode("ascii") + b"\n"
            + body_hash.encode("ascii"))


class Drainer:
    def __init__(self, outbox, key_provider, backend_url: str,
                 admin_token: str = ""):
        self.outbox = outbox
        self.keys = key_provider
        self.backend_url = backend_url.rstrip("/")
        # Only used by --reconcile. The enrol path needs no admin token: it
        # authenticates with the device signing key and nothing else.
        self.admin_token = admin_token
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.session = requests.Session()

    # ------------------------------------------------------------ lifecycle --

    def start(self) -> None:
        requeued = self.outbox.requeue_inflight()
        if requeued:
            log.info("requeued %d inflight rows after restart", requeued)
        self._thread = threading.Thread(target=self._loop, name="drainer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)

    def drain_now(self, max_seconds: float = 60.0) -> int:
        """Drain synchronously until empty or the budget runs out.

        Called at startup BEFORE accepting new enrolments: a Pi rebooted
        mid-run must flush its backlog first, or the operator has no idea
        whether the packs already on the line are recorded.
        """
        deadline = time.time() + max_seconds
        sent = 0
        while time.time() < deadline:
            row = self.outbox.claim_next()
            if row is None:
                break
            if self._send(row):
                sent += 1
        return sent

    # --------------------------------------------------------------- worker --

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                row = self.outbox.claim_next()
                if row is None:
                    self._stop.wait(POLL_INTERVAL)
                    continue
                self._send(row)
            except Exception:
                log.exception("drainer_loop_error")
                self._stop.wait(POLL_INTERVAL)

    def _send(self, row) -> bool:
        raw_body = row["payload"].encode("utf-8")
        idempotency_key = row["idempotency_key"]
        timestamp = str(int(time.time()))
        signature = self.keys.sign(
            build_signed_payload(SIG_ALG, timestamp, idempotency_key, raw_body))

        headers = {
            "Content-Type": "application/json",
            "X-Device-Id": self.keys.device_id(),
            "X-Timestamp": timestamp,
            "X-Sig-Alg": SIG_ALG,
            "X-Signature": signature.hex(),
            "X-Idempotency-Key": idempotency_key,
        }

        try:
            resp = self.session.post(f"{self.backend_url}/api/v2/enrol",
                                     data=raw_body, headers=headers,
                                     timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            delay = self.outbox.mark_retry(row["id"], row["attempts"], str(exc))
            log.warning("enrol_network_error id=%s retry_in=%.0fs: %s",
                        row["id"], delay, exc)
            return False

        if 200 <= resp.status_code < 300:
            tag_index = _tag_index_of(resp)
            self.outbox.mark_acked(row["id"], tag_index)
            log.info("enrol_acked id=%s status=%s", row["id"], resp.status_code)
            return True

        code = _error_code_of(resp)

        # A replayed idempotency key that comes back as tag_already_enrolled on a
        # RETRY means our earlier attempt landed. Treat it as acked.
        if resp.status_code == 409 and code == "tag_already_enrolled" \
                and row["attempts"] > 0:
            self.outbox.mark_acked(row["id"])
            log.info("enrol_acked_via_replay id=%s", row["id"])
            return True

        if resp.status_code in TERMINAL_STATUSES:
            self.outbox.mark_failed(row["id"], f"{resp.status_code} {code}")
            # An operator has to see this. A failed row is a pack on the line
            # with no record, and no amount of retrying will fix it.
            log.error("ENROL FAILED PERMANENTLY id=%s status=%s code=%s — "
                      "quarantine that pack and tell the operator",
                      row["id"], resp.status_code, code)
            return False

        retry_after = resp.headers.get("Retry-After")
        delay = self.outbox.mark_retry(
            row["id"], row["attempts"], f"{resp.status_code} {code}",
            float(retry_after) if retry_after and retry_after.isdigit() else None)
        log.warning("enrol_retry id=%s status=%s retry_in=%.0fs",
                    row["id"], resp.status_code, delay)
        return False

    # -------------------------------------------------------- reconciliation --

    def reconcile(self) -> list[str]:
        """Confirm every acked row actually verifies against the backend.

        Run at the end of every batch. This catches the case where a 2xx was
        received but the row was later lost — rare, but the cost of missing it
        is unverifiable packs in circulation (§12.4).

        Returns the idempotency keys that could not be confirmed.
        """
        if not self.admin_token:
            raise RuntimeError(
                "reconcile needs a batch:read admin token. Mint one offline with "
                "backend/scripts/mint_admin_token.py and pass --admin-token.")
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        unconfirmed: list[str] = []
        for row in self.outbox.acked_rows():
            tag_index = row["tag_index"]
            if not tag_index:
                # Older rows may predate tag_index capture; re-POST is safe
                # because the idempotency key replays the stored response.
                unconfirmed.append(row["idempotency_key"])
                continue
            try:
                resp = self.session.get(
                    f"{self.backend_url}/api/v2/admin/reconcile",
                    params={"tag_index": tag_index}, headers=headers,
                    timeout=REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    unconfirmed.append(row["idempotency_key"])
            except requests.RequestException:
                unconfirmed.append(row["idempotency_key"])
        return unconfirmed


def _error_code_of(resp) -> str:
    try:
        return resp.json().get("error", {}).get("code", "")
    except (ValueError, AttributeError):
        return ""


def _tag_index_of(resp) -> str | None:
    try:
        return resp.json().get("tag_index")
    except (ValueError, AttributeError):
        return None


def new_idempotency_key() -> str:
    return str(uuid.uuid4())


def main() -> int:
    """`python drainer.py [--reconcile]` — run the drainer standalone."""
    import argparse
    import os

    from dotenv import load_dotenv

    import keyprovider
    import outbox as outbox_mod

    load_dotenv()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reconcile", action="store_true",
                    help="verify every acked row against the backend, then exit")
    ap.add_argument("--once", action="store_true", help="drain once, then exit")
    ap.add_argument("--admin-token", default=os.getenv("ADMIN_TOKEN", ""),
                    help="batch:read token, for --reconcile only")
    args = ap.parse_args()

    box = outbox_mod.open_outbox()
    provider = keyprovider.load_key_provider(
        os.getenv("KEY_PROVIDER", "file"),
        privkey_hex=os.getenv("DEVICE_PRIVATE_KEY", ""),
        device_id=os.getenv("DEVICE_ID", ""))
    drainer = Drainer(box, provider, os.getenv("BACKEND_URL", ""),
                      admin_token=args.admin_token)

    if args.reconcile:
        missing = drainer.reconcile()
        print(f"reconcile: {len(missing)} unconfirmed")
        for key in missing:
            print(f"  UNCONFIRMED {key}")
        return 1 if missing else 0

    if args.once:
        sent = drainer.drain_now()
        print(f"drained {sent} rows; depth now {box.depth()}")
        return 0

    drainer.start()
    print(f"drainer running; depth {box.depth()}. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        drainer.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
