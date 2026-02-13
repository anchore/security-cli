import logging

import requests

from anchore_security_cli.identifiers.aliases import Aliases, cve_to_gcve
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class Wordfence(Provider):
    def __init__(self):
        self.url = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
        super().__init__(
            name="Wordfence",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        logging.debug(f"Start downloading latest {self.name} content")
        result = requests.get(self.url, timeout=10).json()
        logging.debug(f"Finish downloading latest {self.name} content")
        logging.debug(f"Start processing {self.name} alias records")
        for r in result.values():
            cve = r.get("cve")
            published = r.get("published")

            if cve and published:
                records.append(
                    ProviderRecord(
                        id=cve,
                        aliases=Aliases.from_list([cve, cve_to_gcve(cve)]),
                        published=self._parse_date(published),
                    ),
                )
        logging.debug(f"Finish processing {self.name} alias records")

        return records
