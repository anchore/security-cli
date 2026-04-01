import json
import logging

import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class GCVE(Provider):
    def __init__(self):
        self._ndjson_urls = [
            "https://vulnerability.circl.lu/dumps/gna-1.ndjson",
            "https://vulnerability.circl.lu/dumps/gna-1337.ndjson",
        ]
        super().__init__(
            name="GCVE identifiers",
        )

    def _normalise_identifier(self, identifier: str) -> str:
        components = identifier.split("-", 1)
        if len(components) < 2:
            return identifier

        prefix = components[0].upper()
        return f"{prefix}-{components[1]}"

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        for url in self._ndjson_urls:
            r = requests.get(
                url,
                timeout=30,
                stream=True,
            )
            r.raise_for_status()

            for record in r.iter_lines():
                gcve = json.loads(record)
                metadata = gcve.get("cveMetadata")

                if not metadata:
                    continue

                gcve_id = metadata.get("vulnId")
                if not gcve_id:
                    continue

                gcve_id = self._normalise_identifier(gcve_id)
                if not gcve_id.startswith("GCVE-"):
                    logging.warning(f"Skipping GCVE record from {url} with unexpected id: {gcve_id!r}")
                    continue

                cve_id = metadata.get("cveId")
                aliases = [gcve_id]
                if cve_id:
                    cve_id = self._normalise_identifier(cve_id)
                    aliases.append(cve_id)

                published = metadata.get("datePublished")
                logging.trace(f"processing GCVE record from {url} for {gcve_id}")

                records.append(
                    ProviderRecord(
                        id=gcve_id,
                        published=self._parse_date(published),
                        aliases=Aliases.from_list(aliases, provider=self.name),
                    ),
                )

        return records
