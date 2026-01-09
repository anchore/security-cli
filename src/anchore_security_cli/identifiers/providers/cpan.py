import logging

import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class CPAN(Provider):
    def __init__(self):
        super().__init__(
            name="CPAN Security Advisories",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        r = requests.get(
            "https://raw.githubusercontent.com/briandfoy/cpan-security-advisory/refs/heads/master/cpan-security-advisory.json",
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        for d in data.get("dists", {}).values():
            for a in d.get("advisories", []):
                record_id = a.get("id")

                if not record_id:
                    continue

                if not record_id.startswith("CPANSA-"):
                    logging.warning(f"Skipping CPAN advisory record with unexpected id: {record_id!r}")
                    continue

                logging.trace(f"processing CPAN data for {record_id}")
                published = self._parse_date(a.get("reported"))

                if not published:
                    continue

                records.append(
                    ProviderRecord(
                        id=record_id,
                        published=published,
                        aliases=Aliases.from_list([record_id, *a.get("cves", [])]),
                    ),
                )

        return records
