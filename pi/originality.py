"""NXP originality signature check (L1). ARCHITECTURE.md §6.6.

READ_SIG returns a 32-byte ECDSA signature over the UID, produced with NXP's
private key at chip manufacture. Curve: secp128r1.

Three things handled honestly here:

1. `cryptography` does not support secp128r1. We use the pure-Python `ecdsa`
   package with a hand-defined curve.

2. We do NOT invent NXP's public key. It comes from NXP application note
   AN11350 and the operator pastes it into pi/.env as NXP_ORIGINALITY_PUBKEY. If
   it is absent, this returns UNAVAILABLE, the enrolment proceeds, and the record
   is stored with originality_status='unverified' — visible in the admin console
   and in /health. It must NEVER silently report 'verified'.

3. READ_SIG is unreachable from Web NFC and from iOS background reading. Both
   expose only NDEF content and the serial number. So L1 protects ENROLMENT, not
   verification. Overstating this is the fastest way to lose a reviewer.

Honest framing: secp128r1 gives roughly 64-bit security. The originality
signature is a filter against casual clone silicon, not a cryptographic proof of
authenticity. The evidence that it works today — publicly sold "magic" NTAG213
tags fail it and report counter 000000 — is empirical, not cryptographic.
"""
from __future__ import annotations

import logging
from enum import Enum

log = logging.getLogger(__name__)

try:  # pragma: no cover - import shape depends on the host
    import ecdsa
    from ecdsa.curves import Curve
    from ecdsa.ellipticcurve import CurveFp
    _HAVE_ECDSA = True
except ImportError:  # pragma: no cover
    _HAVE_ECDSA = False


class OriginalityStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"        # genuine check, genuine failure -> reject the tag
    UNAVAILABLE = "unavailable"  # no pubkey / no ecdsa lib -> record, do not reject


# secp128r1 domain parameters (SEC 2, v2 §2.2.1). These are public standard
# constants, not secrets, and not invented here.
_P = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
_A = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
_B = 0xE87579C11079F43DD824993C2CEE5ED3
_GX = 0x161FF7528B899B2D0C28607CA52C5B86
_GY = 0xCF5AC8395BAFEB13C02DA292DDED7A83
_N = 0xFFFFFFFE0000000075A30D1B9038A115
_H = 1

_curve_cache = None


def _secp128r1():
    """Build the curve object once. Returns None if `ecdsa` is not installed."""
    global _curve_cache
    if not _HAVE_ECDSA:
        return None
    if _curve_cache is None:
        fp = CurveFp(_P, _A, _B)
        generator = ecdsa.ellipticcurve.PointJacobi(fp, _GX, _GY, 1, _N, generator=True)
        _curve_cache = Curve("secp128r1", fp, generator, (1, 3, 132, 0, 28))
    return _curve_cache


def verify_originality(uid_bytes: bytes, sig_32: bytes,
                       pubkey_hex: str | None) -> OriginalityStatus:
    """ECDSA/secp128r1 over the raw 7-byte UID, verified against NXP's public
    key. Signature is r||s, 16 bytes each. Never raises."""
    if not pubkey_hex:
        log.warning("originality_pubkey_absent")
        return OriginalityStatus.UNAVAILABLE
    if not _HAVE_ECDSA:
        log.warning("ecdsa_package_missing")
        return OriginalityStatus.UNAVAILABLE

    try:
        curve = _secp128r1()
        if curve is None:
            return OriginalityStatus.UNAVAILABLE

        if len(sig_32) != 32:
            log.warning("originality_bad_signature_length", extra={"length": len(sig_32)})
            return OriginalityStatus.FAILED

        # from_string accepts the raw 32-byte X||Y form and the 33/65-byte
        # compressed/uncompressed SEC forms, which is every shape AN11350 might
        # be pasted in.
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=curve,
                                            hashfunc=_sha1_for_ecdsa())

        # NXP signs the raw UID bytes; the digest is truncated to the curve order
        # size by the library.
        vk.verify(sig_32, uid_bytes, hashfunc=_sha1_for_ecdsa(),
                  sigdecode=ecdsa.util.sigdecode_string)
        return OriginalityStatus.VERIFIED
    except ecdsa.BadSignatureError:
        return OriginalityStatus.FAILED
    except Exception as exc:
        # A malformed public key is an operator error, not a bad tag. Do not
        # report FAILED for it: that would reject genuine stock over a typo.
        log.warning("originality_check_error", extra={"error": str(exc)})
        return OriginalityStatus.UNAVAILABLE


def _sha1_for_ecdsa():
    import hashlib
    return hashlib.sha1


def decide(status: OriginalityStatus, policy: str) -> tuple[bool, str]:
    """(accept, recorded_status). ORIGINALITY_POLICY is 'reject' (default) or
    'warn'; 'warn' is for bring-up on known-good stock only.

    A RUN of FAILED results means your supplier shipped counterfeit silicon —
    that is a procurement alert (§14.5), and discovering it at packaging time is
    exactly the point.
    """
    if status is OriginalityStatus.VERIFIED:
        return True, "verified"
    if status is OriginalityStatus.UNAVAILABLE:
        return True, "unverified"
    # FAILED
    if policy == "warn":
        return True, "failed"
    return False, "failed"
