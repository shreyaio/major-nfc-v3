"""
Audit logging: every product write and every consumer verify attempt gets a row
in audit_log. Used both for security monitoring and as evidence for the
attack-simulation deliverable (see backend/tests/report.py).
"""

import json
from db import get_connection


def log_audit(event_type: str, tag_uid_hash: str = None, result: str = None,
              source_ip: str = None, user_agent: str = None, detail: dict = None):
    """
    Best-effort audit log write. Never raises — a logging failure must not break
    the request it's trying to log. Callers should call this and move on.
    """
    try:
        conn = get_connection()
        if not conn:
            return
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO audit_log
               (event_type, tag_uid_hash, result, source_ip, user_agent, detail)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                event_type,
                tag_uid_hash,
                result,
                source_ip,
                user_agent,
                json.dumps(detail) if detail is not None else None,
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[AUDIT] Failed to write audit log: {e}")
