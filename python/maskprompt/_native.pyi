"""Type stubs for `maskprompt._native`. Hand-written; keep in sync with
`crates/maskprompt-py/src/lib.rs`."""

from __future__ import annotations

from typing import Any

__version__: str

class MaskpromptError(Exception):
    """Raised on invalid configurations beyond `ValueError`."""

class Masker:
    def __init__(
        self,
        builtins: list[str] | None = None,
        custom: dict[str, list[str]] | None = None,
    ) -> None: ...
    def mask(self, text: str, strategy: str = "tag") -> dict[str, Any]: ...
    def mask_batch(self, texts: list[str], strategy: str = "tag") -> list[dict[str, Any]]: ...
    def __repr__(self) -> str: ...

def builtin_rule_names() -> list[str]:
    """Return the uppercase tags of every built-in rule."""
