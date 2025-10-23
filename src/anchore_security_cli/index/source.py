from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IndexSource:
    git_repo: str
    commit: str
