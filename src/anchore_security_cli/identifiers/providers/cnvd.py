import logging

import json
import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class CNVD(Provider):
    def __init__(self):
        super().__init__(
            name="China National Vulnerability Database",
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
            url="https://vulnerability.circl.lu/dumps/cnvd.ndjson",
            timeout=30,
            stream=True,
        )
        r.raise_for_status()

        for record in r.iter_lines():
            cnvd = json.loads(record)

            cnvd_id = cnvd.get("number")
            if not cnvd_id:
                continue

            cnvd_id = self._normalise_identifier(cnvd_id)
            if not cnvd_id.startswith("CNVD-"):
                logging.warning(f"Skipping CNVD record with unexpected id: {cnvd_id!r}")
                continue

            aliases = [cnvd_id]

            cves = cnvd.get("cves", {}).get("cve")
            if cves:
                # This might be a single entry or a list, so handle both
                if isinstance(cves, dict):
                    cves = [cves]

                for c in cves:
                    cve_id = c.get("cveNumber")
                    if cve_id:
                        aliases.append(self._normalise_identifier(cve_id))

            published = cnvd.get("openTime")
            logging.trace(f"processing CNVD record for {cnvd_id}")

            records.append(
                ProviderRecord(
                    id=cnvd_id,
                    published=self._parse_date(published),
                    aliases=Aliases.from_list(aliases, provider=self.name),
                ),
            )

        return records
