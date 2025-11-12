import logging
import os
from glob import iglob

import orjson
import yaml

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class Go(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="Go Vulnerability Database",
            url="https://github.com/golang/vulndb/archive/refs/heads/master.tar.gz",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "vulndb-master/data/osv/GO-*.json")):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file, "rb") as f:
                data = orjson.loads(f.read())

            record_id = data["id"]
            aliases = Aliases.from_list([record_id, *data.get("aliases", [])])
            published = self._parse_date(data.get("published"))

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=aliases,
                ),
            )

        for file in iglob(os.path.join(content_dir, "vulndb-master/data/excluded/GO-*.yaml")):
            logging.trace(f"processing {self.name} data for {file}")
            with open(file) as f:
                data = yaml.safe_load(f)

            record_id = data["id"]
            cves = data.get("cves", [])
            ghsas = data.get("ghsas", [])
            aliases = Aliases.from_list(cves + ghsas)
            published = self._parse_date(data.get("published"))

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=aliases,
                ),
            )

        return records
