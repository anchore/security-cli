from dataclasses import dataclass

from anchore_security_cli.index.version import IndexVersion


@dataclass(frozen=True, slots=True)
class IndexConfig:
    name: str
    db_name: str
    format: str
    version: IndexVersion
