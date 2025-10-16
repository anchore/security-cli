import json
import logging
import os
from glob import iglob

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class MinimOS(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="MinimOS",
            url="https://osv-vulnerabilities.storage.googleapis.com/MinimOS/all.zip",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "MINI-*.json")):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file) as f:
                data = json.load(f)

            record_id = data["id"]
            aliases = Aliases.from_list([record_id, *data.get("upstream", [])])
            published = self._parse_date(data.get("published"))

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=aliases,
                ),
            )

        return records
