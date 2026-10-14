"""Data model shared by extractor, embedder and store."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class FunctionRecord:
    binary_sha256: str
    binary_name: str
    address: str          # hex entry point, e.g. "0x100003f00"
    name: str
    signature: str
    decompiled: str
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    is_external: bool = False
    is_thunk: bool = False
    size: int = 0         # function body size in bytes
    model: str = ""
    embed_text: str = ""
    vector: list[float] | None = None  # None = deferred embedding (oe embed)

    def to_row(self) -> dict:
        return asdict(self)
