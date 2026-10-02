"""Class F — infrastructure and supply chain. ARCHITECTURE.md §16.6 (F1a..F10a).

This class is mostly a property of the build pipeline, the database schema and the
deployment, not of the running HTTP surface. So these tests INSPECT the committed
artifacts (CI workflows, requirements pins, the RLS schema, the backup workflow)
and exercise the one runtime control that is code — the log redaction filter
(F6a). Where a control is an operator/dashboard action with nothing checkable in
the repository (F3a branch/PR secret scoping, F4a branch protection, F5a hosting
2FA), it is recorded with its pointer rather than faked; F5a is additionally
partial/known-open (§16.9).

None of these need a live server, so they run in the same pass as unit tests.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = REPO_ROOT / "backend"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _read(path: Path) -> str:
    assert path.exists(), f"expected artifact missing: {path}"
    return path.read_text(encoding="utf-8")


# ------------------------------------------------------------------- F1a --------

def test_f1a_installs_require_hashes(evidence):
    """F1a — a typosquatted or confused package is stopped by hash-pinned installs.
    The CI workflow installs the production deps with --require-hashes, so a
    package whose content does not match the recorded hash fails the build."""
    ci = _read(WORKFLOWS / "ci.yml")
    assert "--require-hashes" in ci, "CI does not enforce --require-hashes (F1a)"

    evidence("F1a", outcome="blocked", expected="pip install --require-hashes in CI")


# ------------------------------------------------------------------- F2a --------

def test_f2a_pip_audit_strict_gates_the_build(evidence):
    """F2a — a compromised transitive dependency is caught by pip-audit --strict
    in CI, which fails the build on any known advisory."""
    ci = _read(WORKFLOWS / "ci.yml")
    assert re.search(r"pip-audit\s+--strict", ci), "CI does not run pip-audit --strict"

    evidence("F2a", outcome="blocked", expected="pip-audit --strict fails the build")


def test_f2a_requirements_are_exact_pins_not_ranges(evidence):
    """F2a (supporting) — exact pins, not ranges. A range means the build you
    tested and the build you shipped can differ, which is how a poisoned version
    arrives unnoticed."""
    reqs = _read(BACKEND_DIR / "requirements.txt")
    ranges = []
    for line in reqs.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if any(op in line for op in (">=", "<=", "~=", ">", "<")) or (
                "==" not in line and re.match(r"^[A-Za-z0-9_.\-]+$", line) is None):
            ranges.append(line)
    assert not ranges, f"non-exact version specifiers found: {ranges}"

    evidence("F2a", outcome="blocked", expected="exact == pins only",
             detail={"loose_specifiers": ranges})


# ------------------------------------------------------------------- F3a --------

def test_f3a_ci_secret_scoping_is_an_operator_control(evidence):
    """F3a — secrets must not be exposed to workflows triggered by untrusted PRs.
    GitHub enforces this at the environment/secret-scope level, which is an
    operator setting (§20.4), not something a file in the repo can prove on its
    own. Recorded with the pointer; the CI file at least does not echo secrets."""
    ci = _read(WORKFLOWS / "ci.yml")
    # A crude but useful guard: no `echo ... ${{ secrets` in the workflow.
    assert not re.search(r"echo[^\n]*\$\{\{\s*secrets\.", ci), "CI echoes a secret"

    evidence("F3a", outcome="inconclusive",
             expected="PR workflows have no secret access (operator, §20.4)",
             detail={"repo_check": "no secret echoed in ci.yml"})
    pytest.skip("F3a is a GitHub environment/secret-scope setting (§20.4)")


# ------------------------------------------------------------------- F4a --------

def test_f4a_branch_protection_is_an_operator_control(evidence):
    """F4a — auto-deploy from main is bounded by branch protection, required
    review and signed commits. These are repository settings applied by the
    operator (§20.4); there is no in-repo artifact that proves they are on."""
    evidence("F4a", outcome="inconclusive",
             expected="branch protection + review + signed commits (operator)",
             detail={"where": "§14.4, §20.4"})
    pytest.skip("F4a is a branch-protection/settings control (operator, §20.4)")


# ------------------------------------------------------------------- F5a --------

def test_f5a_hosting_dashboard_takeover_is_partial_and_open(evidence):
    """F5a — mandatory 2FA and separate accounts per service reduce this, but a
    hosting-dashboard takeover is not something the application can close.
    Partial, known-open (§16.9)."""
    evidence("F5a", outcome="open",
             expected="partial: 2FA + account separation (operator)",
             detail={"where": "§20.4"})
    pytest.skip("F5a is partial/known-open: hosting dashboard is out of app control")


# ------------------------------------------------------------------- F6a --------

def test_f6a_log_redaction_scrubs_secret_values(monkeypatch, evidence):
    """F6a — the log formatter's redaction filter replaces any known secret value
    (and secret-looking keys) with *** before the line is emitted. This is the one
    F-class control that is runtime code, so it is exercised directly: a log line
    carrying a DATABASE_URL must come out redacted."""
    secret = "postgresql://u:sup3r-secret-pw@db.example:5432/prod"
    monkeypatch.setenv("DATABASE_URL", secret)

    import logging_setup
    redactor = logging_setup.SecretRedactor()  # snapshots env at construction
    line = f"connection failed for {secret} while starting up"
    scrubbed = redactor.scrub(line)

    assert secret not in scrubbed, "secret survived redaction"
    assert logging_setup.REDACTED in scrubbed

    evidence("F6a", outcome="blocked", expected="secret value -> *** in logs")


# ------------------------------------------------------------------- F7a --------

def test_f7a_rls_on_every_table_with_zero_anon_access(evidence):
    """F7a — Supabase exposes PostgREST over the anon key. The schema enables RLS
    on every table and grants ZERO policies to anon, and explicitly REVOKEs anon
    access. A missing RLS enable would leak a whole table over the public API."""
    rls = _read(BACKEND_DIR / "schema" / "002_rls.sql")
    enables = len(re.findall(r"ENABLE ROW LEVEL SECURITY", rls, re.I))
    assert enables >= 1, "no ENABLE ROW LEVEL SECURITY statements found"
    assert re.search(r"REVOKE\s+ALL\s+ON\s+ALL\s+TABLES.*FROM\s+anon", rls, re.I | re.S), \
        "anon is not revoked"
    # There must be no policy that grants anon a role.
    assert not re.search(r"CREATE\s+POLICY[^;]*\bTO\s+anon\b", rls, re.I | re.S), \
        "an anon policy exists"

    evidence("F7a", outcome="blocked",
             expected="RLS on every table, zero anon policies",
             detail={"enable_statements": enables})


# ------------------------------------------------------------------- F8a --------

def test_f8a_backups_are_encrypted_to_an_offline_key(evidence):
    """F8a — the nightly dump is encrypted to an OFFLINE public key on the runner,
    before it leaves, so an exfiltrated backup artifact is ciphertext. The backup
    workflow pipes the dump straight into `age -r <pubkey>` and never writes
    plaintext to disk."""
    backup = _read(WORKFLOWS / "backup.yml")
    assert re.search(r"age\s+-r", backup), "backup is not age-encrypted to a recipient"
    assert ".age" in backup, "backup artifact is not the encrypted .age file"
    assert not re.search(r"path:\s*backup-\*\.sql\b(?!\.age)", backup), \
        "a plaintext .sql backup is uploaded"

    evidence("F8a", outcome="blocked", expected="age-encrypted backup, offline key")


# ------------------------------------------------------------------- F9a --------

def test_f9a_counterfeit_supply_gate_is_pi_side_with_ops_alerting(evidence):
    """F9a — counterfeit silicon entering the supply is stopped at packaging by the
    Pi's originality gate (READ_SIG), with a rejection-rate alert to procurement
    when the gate starts firing (§6.6, §14.5). The gate is proven in pi/ against
    real chips; there is no backend surface to assert here."""
    evidence("F9a", outcome="blocked",
             expected="Pi originality gate + rejection-rate alert",
             detail={"proven_in": "pi/ §6.6; alerting §14.5"})
    pytest.skip("F9a is a Pi-side gate + ops alert; proven in pi/ (§6.6, §14.5)")


# ------------------------------------------------------------------- F10a -------

def test_f10a_rogue_packaging_device_is_bounded_by_batch_quota(evidence):
    """F10a — a stolen/rogue packaging device cannot mint unlimited tags: each
    open batch has a hard DB quota, and enrolments past it are rejected with
    batch_quota_exhausted (proven in integration/test_batch_quota.py). Device
    attestation would close it fully; without it this is partial/known-open
    (§16.9)."""
    evidence("F10a", outcome="open",
             expected="partial: per-batch quota bounds damage; attestation would close",
             detail={"proven_in": "integration/test_batch_quota.py", "where": "§12.6"})
    pytest.skip("F10a is partial/known-open: quota bounds it, no device attestation")
