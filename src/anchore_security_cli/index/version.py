from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IndexVersion:
    model: int
    revision: int
    addition: int

    def __str__(self) -> str:
        return f"{self.model}.{self.revision}.{self.addition}"
