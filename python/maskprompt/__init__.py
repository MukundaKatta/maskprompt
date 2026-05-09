"""Sub-millisecond PII redaction for prompts before they reach an LLM.

The native module ``maskprompt._native`` does the regex + Aho-Corasick
work in Rust. This module wraps it in a typed dataclass-shaped API so
callers don't have to dig through dicts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from importlib import metadata
from typing import Any, Final

from maskprompt._native import (
    Masker as _NativeMasker,
)
from maskprompt._native import (
    MaskpromptError,
    builtin_rule_names,
)


def _read_version() -> str:
    try:
        return metadata.version("maskprompt")
    except metadata.PackageNotFoundError:
        return "0.0.0"


__version__: Final[str] = _read_version()


class BuiltinRule(str, Enum):
    """Names of the built-in detectors. String-valued so they are JSON-friendly."""

    EMAIL = "EMAIL"
    US_PHONE = "US_PHONE"
    US_SSN = "US_SSN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    CREDIT_CARD = "CREDIT_CARD"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    JWT = "JWT"

    @classmethod
    def all(cls) -> list[BuiltinRule]:
        """Every built-in rule."""
        return list(cls)


class Strategy(str, Enum):
    """Replacement strategy applied to each match."""

    TAG = "tag"
    HASH = "hash"
    FIXED = "fixed"
    REMOVE = "remove"


@dataclass(frozen=True)
class MaskMatch:
    """One redacted span. Byte offsets into the original input."""

    kind: str
    start: int
    end: int
    value: str


@dataclass(frozen=True)
class MaskResult:
    """Result of [`Masker.mask`]."""

    masked: str
    matches: list[MaskMatch]


class Masker:
    """Compiled detector set. Construct once, reuse across calls."""

    def __init__(
        self,
        *,
        builtins: Iterable[BuiltinRule | str] | None = None,
        custom: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        # Accept either the `BuiltinRule` enum or a plain uppercase string;
        # the native layer rejects unknown strings with a clear ValueError.
        builtin_strs: list[str] = []
        for r in builtins or []:
            builtin_strs.append(r.value if isinstance(r, BuiltinRule) else str(r))
        custom_d: dict[str, list[str]] = {k: list(v) for k, v in custom.items()} if custom else {}
        self._inner = _NativeMasker(builtin_strs, custom_d)

    def mask(self, text: str, *, strategy: Strategy = Strategy.TAG) -> MaskResult:
        """Run all detectors against `text` and apply `strategy`."""
        raw: dict[str, Any] = self._inner.mask(text, strategy.value)
        return _result_from_dict(raw)

    def mask_batch(
        self,
        texts: Sequence[str],
        *,
        strategy: Strategy = Strategy.TAG,
    ) -> list[MaskResult]:
        """Mask many inputs in one call. The same `strategy` applies to each."""
        raws: list[dict[str, Any]] = self._inner.mask_batch(list(texts), strategy.value)
        return [_result_from_dict(r) for r in raws]


def _result_from_dict(raw: dict[str, Any]) -> MaskResult:
    matches = [MaskMatch(**m) for m in raw["matches"]]
    return MaskResult(masked=raw["masked"], matches=matches)


__all__ = [
    "BuiltinRule",
    "MaskMatch",
    "MaskResult",
    "Masker",
    "MaskpromptError",
    "Strategy",
    "__version__",
    "builtin_rule_names",
]
