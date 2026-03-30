import logging

import orjson
import requests

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord


class JVNDB(Provider):
    def __init__(self):
        super().__init__(
            name="Japan Vulnerability Notes",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        r = requests.get(
            url="https://vulnerability.circl.lu/dumps/jvndb.ndjson",
            timeout=30,
            stream=True,
        )
        r.raise_for_status()

        for record in r.iter_lines():
            jvndb = orjson.loads(record)

            jvndb_id = jvndb.get("sec:identifier")
            if not jvndb_id:
                continue

            if not jvndb_id.startswith("JVNDB-"):
                logging.warning(f"Skipping JVNDB record with unexpected id: {jvndb_id!r}")
                continue

            aliases: set[str] = {jvndb_id}
            refs = jvndb.get("sec:references", [])
            if refs:
                # This might be a single entry or a list, so handle both
                if isinstance(refs, dict):
                    refs = [refs]

                for ref in refs:
                    ref_id = ref.get("@id")
                    if ref_id:
                        aliases.add(ref_id)

            published = jvndb.get("dcterms:issued")
            logging.trace(f"processing JVNDB record for {jvndb_id}")

            records.append(
                ProviderRecord(
                    id=jvndb_id,
                    published=self._parse_date(published),
                    aliases=Aliases.from_list(list(aliases), provider=self.name),
                ),
            )

        return records
