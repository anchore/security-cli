import logging
import os
from glob import iglob

import orjson

from anchore_security_cli.identifiers.aliases import Aliases, cve_to_gcve
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class CVE5(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="CVE5",
            url="https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "cvelistV5-main/cves/**/CVE-*.json"), recursive=True):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing CVE5 data for {file}")
            with open(file, "rb") as f:
                data = orjson.loads(f.read())

            metadata = data.get("cveMetadata")
            if not metadata:
                continue

            record_id = metadata["cveId"]
            published = self._parse_date(metadata.get("datePublished", metadata.get("dateRejected")))

            if not published:
                continue

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=Aliases.from_list([record_id, cve_to_gcve(record_id)]),
                ),
            )

        return records
