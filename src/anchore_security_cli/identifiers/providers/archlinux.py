import logging

import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class ArchLinux(Provider):
    def __init__(self):
        super().__init__(
            name="Arch Linux Security Advisories",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        r = requests.get(
            "https://security.archlinux.org/issues/all.json",
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        for avg in data:
            identifiers = [avg["name"], *avg.get("advisories", [])]
            aliases = avg.get("issues", [])

            for record_id in identifiers:
                if not record_id.startswith(("AVG-", "ASA-")):
                    logging.warning(f"Skipping Arch Linux advisory record with unexpected id: {record_id!r}")
                    continue

                logging.trace(f"processing Arch Linux data for {record_id}")

                records.append(
                    ProviderRecord(
                        id=record_id,
                        published=self._parse_date(None),
                        aliases=Aliases.from_list([record_id, *aliases]),
                    ),
                )

        return records
