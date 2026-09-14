"""The `m` parameter parser, against tests/vectors/mirror.json.
ARCHITECTURE.md §6.3, §9.6.

Hostile input to this parser is a 400, never a verdict. Everything an attacker
controls arrives here, so the rules are strict and the failures are boring.
"""
from __future__ import annotations

import pytest

from errors import MalformedParameters
from mirror import MAX_PARAM_LEN, parse_mirror, single_param

VALID_TOKEN = "9F3C" + "0" * 28


def test_valid_cases_from_vectors(mirror_vectors):
    for case in mirror_vectors["valid"]:
        parsed, token = parse_mirror(case["m"], VALID_TOKEN)
        assert parsed.uid == case["uid"], case
        assert parsed.counter == case["counter"], case
        assert parsed.placeholder == case["placeholder"], case
        assert token == VALID_TOKEN


def test_invalid_cases_from_vectors(mirror_vectors):
    for case in mirror_vectors["invalid"]:
        with pytest.raises(MalformedParameters):
            parse_mirror(case["m"], VALID_TOKEN)


def test_token_cases_from_vectors(mirror_vectors):
    good_m = mirror_vectors["valid"][0]["m"]
    for token in mirror_vectors["tokens"]["valid"]:
        parse_mirror(good_m, token)
    for case in mirror_vectors["tokens"]["invalid"]:
        with pytest.raises(MalformedParameters):
            parse_mirror(good_m, case["t"])


def test_b6_token_is_mandatory():
    """There is no UID-only fallback path anywhere in this codebase. A UID is
    printed on the outside of every chip; a 128-bit token is not."""
    with pytest.raises(MalformedParameters):
        parse_mirror("04A1B2C3D4E5F6x0001A7", None)
    with pytest.raises(MalformedParameters):
        parse_mirror("04A1B2C3D4E5F6x0001A7", "")


def test_b4_length_cap_applies_before_the_regex():
    """An oversized parameter is rejected on length, so the regex never becomes
    a DoS surface. A 100 KB `m` must not be matched against anything."""
    with pytest.raises(MalformedParameters):
        parse_mirror("A" * (MAX_PARAM_LEN + 1), VALID_TOKEN)
    with pytest.raises(MalformedParameters):
        parse_mirror("04A1B2C3D4E5F6x0001A7", "A" * 100_000)


def test_b5_unicode_is_normalised_to_one_canonical_value():
    """B5. NFKC runs BEFORE the pattern match, so a full-width digit becomes an
    ASCII one and the input is accepted as its canonical form.

    The security property is NOT that odd Unicode is rejected — it is that the
    edge Worker and the origin independently reach the SAME canonical value.
    edge/src/canonicalise.js applies exactly this sequence (normalize('NFKC'),
    trim, toUpperCase, then the identical pattern), so nothing can be smuggled
    past one parser and read differently by the other (B9).

    Normalising after matching would be the bug: the pattern would reject a
    perfectly resolvable input, or worse, two layers would disagree about which
    tag was being asked about."""
    # NFKC folds full-width digits AND superscripts to plain ASCII digits, so
    # both of these resolve to the same tag as the plain form.
    ascii_form = "04A1B2C3D4E5F6x0001A7"
    from_ascii, _ = parse_mirror(ascii_form, VALID_TOKEN)

    for equivalent in ["０４A1B2C3D4E5F6x0001A7",   # full-width 0 and 4
                       "04A1B2C3D4E5F⁶x0001A7"]:        # superscript six
        parsed, _ = parse_mirror(equivalent, VALID_TOKEN)
        assert parsed.uid == from_ascii.uid == "04A1B2C3D4E5F6"
        assert parsed.counter == from_ascii.counter

    # Characters that do NOT fold to hex are still rejected outright:
    # look-alike letters from other scripts, and invisible formatting marks that
    # would otherwise let two layers disagree about where a field ends.
    for hostile in ["а0A1B2C3D4E5F6x0001A",    # Cyrillic small a
                    "Α0A1B2C3D4E5F6x0001A",    # Greek capital alpha
                    "​04A1B2C3D4E5F6x0001A7",  # zero-width space
                    "04A1B2C3D4E5F6x0001A7‏"]: # right-to-left mark
        with pytest.raises(MalformedParameters):
            parse_mirror(hostile, VALID_TOKEN)


def test_lowercase_is_accepted_and_uppercased():
    parsed, token = parse_mirror("04a1b2c3d4e5f6x0001a7", VALID_TOKEN.lower())
    assert parsed.uid == "04A1B2C3D4E5F6"
    assert token == VALID_TOKEN


def test_placeholder_detection():
    """B7 — uid all zeros AND counter zero means the mirror never fired."""
    parsed, _ = parse_mirror("00000000000000x000000", VALID_TOKEN)
    assert parsed.placeholder is True

    # A real UID with a zero counter is NOT a placeholder: it is a tag whose
    # counter is genuinely at zero, which the state machine handles normally.
    parsed, _ = parse_mirror("04A1B2C3D4E5F6x000000", VALID_TOKEN)
    assert parsed.placeholder is False
    assert parsed.counter == 0


class _Args:
    """Minimal stand-in for Flask's MultiDict."""

    def __init__(self, values):
        self._values = values

    def getlist(self, name):
        return list(self._values.get(name, []))


def test_b8_duplicate_parameters_are_rejected():
    """Flask's args.get silently takes the FIRST value. A front layer that takes
    the first and a back layer that takes the last is the whole of parameter
    pollution — rejecting duplicates removes the disagreement."""
    assert single_param(_Args({"m": ["one"]}), "m") == "one"
    with pytest.raises(MalformedParameters):
        single_param(_Args({"m": ["one", "two"]}), "m")
    with pytest.raises(MalformedParameters):
        single_param(_Args({}), "m")


def test_sql_injection_shaped_input_is_just_a_400():
    """Not that it could work — every query is parameterised (§15.3 rule 6) —
    but it must not reach the database layer at all."""
    for hostile in ["'; DROP TABLE products;--",
                    "04A1B2C3D4E5F6x0001A7' OR '1'='1",
                    "../../etc/passwd",
                    "<script>alert(1)</script>"]:
        with pytest.raises(MalformedParameters):
            parse_mirror(hostile, VALID_TOKEN)
