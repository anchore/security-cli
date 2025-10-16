import json
import logging
import os
from glob import glob

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class Chainguard(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="Chainguard",
            url="https://osv-vulnerabilities.storage.googleapis.com/Chainguard/all.zip",
        )

    def _parse_aliases(self, data: dict) -> list[str]:
        """
        The Chainguard OSV data seems to use both `aliases` and `related` interchangeably even though
        they should mean something slightly different.  For now, assume if there are no aliases and there
        is only a single CVE and/or GHSA in related then they should actually be aliases
        """

        aliases = data.get("aliases", [])
        if aliases:
            return aliases

        related = data.get("related", [])
        ghsas = set()
        cves = set()
        for r in related:
            if r.startswith("CVE-"):
                cves.add(r)
            elif r.startswith("GHSA-"):
                ghsas.add(r)

        if len(cves) == 1:
            aliases.extend(cves)

        if len(ghsas) == 1:
            aliases.extend(ghsas)

        return aliases

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in glob(os.path.join(content_dir, "CGA-*.json")):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file) as f:
                data = json.load(f)

            record_id = data["id"]
            aliases = Aliases.from_list([record_id, *self._parse_aliases(data)])
            published = self._parse_date(data.get("published"))

            records.append(
                ProviderRecord(
                    id=record_id,
                    published=published,
                    aliases=aliases,
                ),
            )

        return records
