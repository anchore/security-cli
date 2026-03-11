import logging

import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class ENISA(Provider):
    def __init__(self):
        super().__init__(
            name="ENISA",
        )

    def _normalise_identifier(self, identifier: str) -> str:
        components = identifier.split("-", 1)
        if len(components) < 2:
            return identifier

        prefix = components[0].upper()
        return f"{prefix}-{components[1]}"

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        r = requests.get(
            url="https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping",
            timeout=30,
            stream=True,
        )
        r.raise_for_status()

        for record in r.iter_lines():
            record = record.decode("utf-8")

            if not record.startswith("EUVD-"):
                continue

            components = record.split(",", 1)

            if len(components) != 2:
                logging.warning(f"{self.name}: Skipping unexpected row {record}")

            euvd_id = self._normalise_identifier(components[0])
            cve_id = self._normalise_identifier(components[1])

            logging.trace(f"{self.name}: processing record for {euvd_id}")

            records.append(
                ProviderRecord(
                    id=euvd_id,
                    published=self._parse_date(None),
                    aliases=Aliases.from_list([euvd_id, cve_id], provider=self.name),
                ),
            )

        return records
