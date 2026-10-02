"""Integration fixtures — a LIVE SERVER over real HTTP. ARCHITECTURE.md §17.3.

Not Flask's test client. A mock cannot catch a middleware ordering bug, a CORS
misconfiguration, a header the WSGI layer strips, or a rate limiter that counts
per worker instead of globally. v1 tested against a live server and was right to
(§5.2); this keeps that.

These tests run against a SEPARATE Supabase project, or against a batch reserved
for testing. They never mutate production data.

The live-server fixtures themselves (`session`, `server_config`,
`field_recipient_pub`, `test_batch`, `make_tag`, `enrol`, `verify`, `new_key`)
now live in the parent ``tests/conftest.py``. They were lifted there so the
sibling attack suite in ``tests/attacks/`` can reuse them unchanged — pytest
shares fixtures down a subtree, not across siblings. Both directories inherit
them from the common ancestor; nothing here needs to redefine them.

Everything skips cleanly when TEST_BASE_URL is unset, so `pytest tests/unit`
stays the thing that runs everywhere.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
