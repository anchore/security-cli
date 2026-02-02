import logging
import os
from glob import iglob

import orjson

from anchore_security_cli.identifiers.aliases import Aliases, generate_all_openeuler_id_variants
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class OpenEuler(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="openEuler",
            url="https://osv-vulnerabilities.storage.googleapis.com/openEuler/all.zip",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "OESA-*.json")):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file, "rb") as f:
                data = orjson.loads(f.read())

            record_id = data["id"]
            aliases = Aliases.from_list([record_id, *data.get("upstream", [])])
            published = self._parse_date(data.get("published"))

            for v in generate_all_openeuler_id_variants(record_id):
                records.append(
                    ProviderRecord(
                        id=v,
                        published=published,
                        aliases=aliases,
                    ),
                )

        return records
