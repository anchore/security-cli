import json
import logging
import os
from glob import iglob

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.models.alteration import Alteration
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord

alterations: list[Alteration] = [
    Alteration(identifier="MAL-2024-3834", drop={"GHSA-r6x6-85h3-39v6"}),
]

class OpenSSFMaliciousPackages(ArchiveProvider):
    def __init__(self):
        self._indexed_alterations = {a.identifier:a for a in alterations}
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
            with open(file) as f:
                data = json.load(f)

            record_id = data["id"]

            aliases = data.get("aliases", [])
            if record_id in self._indexed_alterations:
                alteration = self._indexed_alterations[record_id]
                if alteration.drop and aliases:
                    aliases = list(set(aliases)-alteration.drop)

                if alteration.add:
                    for identifier in alteration.add:
                        aliases.append(identifier)

            aliases = Aliases.from_list([record_id, *aliases], provider=self.name)
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
