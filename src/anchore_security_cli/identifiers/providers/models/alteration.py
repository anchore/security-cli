from dataclasses import dataclass


@dataclass(frozen=True)
class Alteration:
    identifier: str
    drop: set[str] | None = None
    add: set[str] | None = None
