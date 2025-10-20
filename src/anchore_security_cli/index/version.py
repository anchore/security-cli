from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IndexVersion:
    model: int
    revision: int
    addition: int
