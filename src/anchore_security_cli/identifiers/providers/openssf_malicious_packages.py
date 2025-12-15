import logging
import os
from glob import iglob

import orjson

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class OpenSSFMaliciousPackages(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="OpenSSF Malicious Packages",
            url="https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "malicious-packages-main/osv/**/MAL-*.json"), recursive=True):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file, "rb") as f:
                data = orjson.loads(f.read())

            record_id = data["id"]
            aliases = Aliases.from_list([record_id, *data.get("aliases", [])])
            published = self._parse_date(data.get("published"))

            if not record_id.startswith("MAL-"):
                logging.warning(f"Skipping OpenSSF Malicious Packages record with unexpected id: {record_id!r}")
                continue

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=aliases,
                ),
            )

        return records
