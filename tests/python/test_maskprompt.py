"""End-to-end tests for the Python facade."""

from __future__ import annotations

import pytest
from maskprompt import (
    BuiltinRule,
    Masker,
    MaskMatch,
    MaskResult,
    Strategy,
    __version__,
    builtin_rule_names,
)


def test_version_present() -> None:
    assert isinstance(__version__, str)
    assert __version__ != ""


def test_builtin_rule_names_complete() -> None:
    names = builtin_rule_names()
    assert "EMAIL" in names
    assert "CREDIT_CARD" in names
    assert "JWT" in names


def test_email_redaction_basic() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("ping alice@example.com please")
    assert r.masked == "ping <EMAIL> please"
    assert len(r.matches) == 1
    assert r.matches[0].kind == "EMAIL"
    assert r.matches[0].value == "alice@example.com"


def test_no_match_passthrough() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("nothing here")
    assert r.masked == "nothing here"
    assert r.matches == []


def test_credit_card_luhn_filter() -> None:
    m = Masker(builtins=[BuiltinRule.CREDIT_CARD])
    valid = "paid 4111-1111-1111-1111 today"
    invalid = "order 1234-5678-1234-5678"
    assert m.mask(valid).masked == "paid <CREDIT_CARD> today"
    assert m.mask(invalid).masked == invalid


def test_custom_keywords_case_insensitive() -> None:
    m = Masker(custom={"customer": ["Acme Corp", "Globex"]})
    r = m.mask("call ACME corp and globex tomorrow")
    assert r.masked == "call <CUSTOMER> and <CUSTOMER> tomorrow"
    assert len(r.matches) == 2


def test_hash_strategy_stable() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    a = m.mask("a@b.com", strategy=Strategy.HASH).masked
    b = m.mask("a@b.com", strategy=Strategy.HASH).masked
    c = m.mask("c@d.com", strategy=Strategy.HASH).masked
    assert a == b
    assert a != c
    assert a.startswith("<EMAIL:")
    assert a.endswith(">")


def test_fixed_strategy() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("hi a@b.com bye", strategy=Strategy.FIXED)
    assert "█" in r.masked
    assert r.masked.startswith("hi ")
    assert r.masked.endswith(" bye")


def test_remove_strategy() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("hi a@b.com bye", strategy=Strategy.REMOVE)
    assert r.masked == "hi  bye"


def test_match_offsets_byte_accurate() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    text = "hi alice@example.com bye"
    r = m.mask(text)
    m0 = r.matches[0]
    assert text[m0.start : m0.end] == m0.value


def test_mask_batch() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    texts = ["hi a@b.com", "no match", "x@y.io and z@w.io"]
    results = m.mask_batch(texts)
    assert len(results) == 3
    assert results[0].masked == "hi <EMAIL>"
    assert results[1].masked == "no match"
    assert results[2].masked == "<EMAIL> and <EMAIL>"
    assert len(results[2].matches) == 2


def test_empty_masker_rejected() -> None:
    with pytest.raises(ValueError, match="no rules"):
        Masker()


def test_unknown_rule_rejected() -> None:
    with pytest.raises(ValueError, match="unknown built-in rule"):
        Masker(builtins=["NOT_A_RULE"])  # type: ignore[list-item]


def test_unknown_strategy_rejected() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    with pytest.raises(ValueError, match="unknown strategy"):
        m._inner.mask("a@b.com", "nonsense")  # exercise the native check


def test_dataclass_shapes() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("a@b.com")
    assert isinstance(r, MaskResult)
    assert isinstance(r.matches[0], MaskMatch)


def test_multiple_rules_resolve_left_to_right() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL, BuiltinRule.CREDIT_CARD])
    r = m.mask("email a@b.com card 4111-1111-1111-1111 done")
    assert r.masked == "email <EMAIL> card <CREDIT_CARD> done"
    assert len(r.matches) == 2
    assert r.matches[0].start < r.matches[1].start


def test_unicode_input_preserved() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    r = m.mask("hello 世界 a@b.com 🌍")
    assert r.masked == "hello 世界 <EMAIL> 🌍"


def test_aws_key_redacted() -> None:
    m = Masker(builtins=[BuiltinRule.AWS_ACCESS_KEY])
    r = m.mask("key AKIAIOSFODNN7EXAMPLE leaked")
    assert r.masked == "key <AWS_ACCESS_KEY> leaked"


def test_jwt_redacted() -> None:
    m = Masker(builtins=[BuiltinRule.JWT])
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.signature_part_long_enough"
    r = m.mask(f"auth: {jwt} ok")
    assert r.masked == "auth: <JWT> ok"


def test_all_builtins_at_once() -> None:
    m = Masker(builtins=BuiltinRule.all())
    r = m.mask("ip 10.0.0.1 ssn 123-45-6789 mail a@b.com")
    kinds = {mt.kind for mt in r.matches}
    assert {"IPV4", "US_SSN", "EMAIL"}.issubset(kinds)


def test_match_attributes_immutable() -> None:
    m = Masker(builtins=[BuiltinRule.EMAIL])
    mt = m.mask("a@b.com").matches[0]
    with pytest.raises((AttributeError, Exception)):
        mt.kind = "OTHER"  # type: ignore[misc]
