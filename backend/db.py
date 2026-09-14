"""Pooled Postgres access. ARCHITECTURE.md §9.3.

Two things carried over from v1 verbatim because they were right:

  - the `sslmode=require` injection. Supabase requires TLS, and a pasted
    connection string may or may not already say so.
  - the SESSION POOLER connection string. The direct Supabase hostname
    (db.<ref>.supabase.co) resolves IPv6-only and fails to connect from Render;
    the symptom is a database error in production while the same code works
    locally. Nothing here enforces that, but it is why the README says it twice.

One thing that changed: v1 called get_connection() and leaked a connection on
every error path that returned early (D24). The context manager below always
returns the connection to the pool and always rolls back on an exception.

maxconn must stay <= Supabase's free-tier pooler limit. With gunicorn
--workers 2, total connections are 2 x db_pool_max, so db_pool_max = 6 -> 12.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

from errors import ServiceUnavailable

log = logging.getLogger(__name__)

_pool: ThreadedConnectionPool | None = None


def _with_sslmode(url: str) -> str:
    """Supabase's Postgres requires an SSL connection. If the connection string
    doesn't already specify sslmode, add sslmode=require so psycopg2 negotiates
    TLS instead of failing (or silently connecting unencrypted)."""
    if not url or "sslmode=" in url:
        return url
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["sslmode"] = ["require"]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def init_pool(cfg) -> None:
    global _pool
    if _pool is not None:
        return
    try:
        _pool = ThreadedConnectionPool(
            minconn=1, maxconn=cfg.db_pool_max, dsn=_with_sslmode(cfg.database_url))
    except psycopg2.Error as exc:
        # Do not include the DSN: it contains the password. The redactor would
        # catch it anyway, but not relying on that is cheaper than relying on it.
        log.error("db_pool_init_failed", extra={"error": exc.__class__.__name__})
        raise ServiceUnavailable("database pool could not be created") from exc


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None


def pool_ready() -> bool:
    return _pool is not None


@contextmanager
def connection(*, write: bool = False):
    """Always returns the connection to the pool. Rolls back on any exception.

    Use `write=True` for anything that mutates: the commit happens here, once,
    after the block completes, which is what makes multi-statement writes a
    single transaction (§15.3 rule 3).
    """
    if _pool is None:
        raise ServiceUnavailable("database pool not initialised")
    try:
        conn = _pool.getconn()
    except psycopg2.pool.PoolError as exc:
        raise ServiceUnavailable("no database connection available",
                                 retry_after=2) from exc
    try:
        yield conn
        if write:
            conn.commit()
    except Exception:
        try:
            conn.rollback()
        except psycopg2.Error:
            pass  # the connection is already broken; putconn will discard it
        raise
    finally:
        _pool.putconn(conn)


def healthcheck() -> bool:
    """Cheap reachability probe for /health. Never raises, never leaks detail."""
    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            return cur.fetchone() is not None
    except Exception as exc:
        log.warning("db_healthcheck_failed", extra={"error": exc.__class__.__name__})
        return False
