import logging
import os
from glob import iglob

import orjson

from anchore_security_cli.identifiers.aliases import Aliases, generate_all_bellsoft_id_variants
from anchore_security_cli.identifiers.providers.provider import ArchiveProvider, ProviderRecord


class BellSoft(ArchiveProvider):
    def __init__(self):
        super().__init__(
            name="BellSoft",
            url="https://osv-vulnerabilities.storage.googleapis.com/BellSoft%20Hardened%20Containers/all.zip",
        )

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        records = []
        for file in iglob(os.path.join(content_dir, "BELL-*.json")):
            if not os.path.isfile(file):
                continue

            logging.trace(f"processing {self.name} data for {file}")
            with open(file, "rb") as f:
                data = orjson.loads(f.read())

            record_id = Aliases.normalize(data["id"])

            # Most of the OSV entries are just BELL-<CVE id> which are not useful, but some have
            # the actual BELL-SA id embedded in the references and we do want to collect those
            if record_id.startswith("CVE-"):
                for r in data.get("references", []):
                    url = r.get("url")

                    if not url or not url.startswith("https://docs.bell-sw.com/security/advisories/"):
                        continue

                    bell_sa_id = url.strip("/").split("/")[-1]

                    if not bell_sa_id.startswith("BELL-SA-"):
                        continue

                    for v in generate_all_bellsoft_id_variants(bell_sa_id):
                        records.append(
                            ProviderRecord(
                                id=v,
                                aliases=Aliases.from_list([record_id]),
                                published=self._parse_date(data.get("published")),
                            ),
                        )
            else:
                logging.warning(f"Skipping unexpected BellSoft identifier {record_id}")

        return records
