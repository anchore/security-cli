import json
import logging
import os
import sqlite3
import tempfile
from datetime import UTC, datetime

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers.provider import Provider, ProviderRecord
from anchore_security_cli.utils import execute_command


class GrypeDB(Provider):
    def __init__(self):
        super().__init__(
            name="Grype DB",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        with tempfile.TemporaryDirectory() as tmp:
            logging.debug(f"Start fetching latest {self.name} content to {tmp}")
            os.environ["GRYPE_DB_CACHE_DIR"] = tmp
            execute_command("grype db update")
            logging.debug(f"Finish fetching latest {self.name} content to {tmp}")
            path = os.path.join(tmp, "6/vulnerability.db")
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row # Allows accessing cursor results by column name
                logging.debug(f"Start processing {self.name} alias records")
                cur = conn.cursor()
                # For now just limit to the identifiers we won't currently pull elsewhere due to
                # lack of convenient bulk downloads: chainguard libs, oracle linux, and amazon linux
                cur.execute("""
                SELECT
                    advisory,
                    json_group_array(alias) aliases,
                    min(published) as published
                FROM
                (
                    SELECT
                        a.name as advisory,
                        a.alias as alias,
                        v.published_date as published
                    FROM
                        vulnerability_aliases a
                        INNER JOIN vulnerability_handles v
                            ON v.name=a.name
                    WHERE
                        a.name like "CGA-%"
                        or a.name like "ELSA-%"
                        or a.name like "ALAS%"
                    UNION ALL
                    SELECT
                        json_extract(refs.value, '$.id') as advisory,
                        v.name as alias,
                        COALESCE(json_extract(ranges.value, '$.fix.detail.available.date'), v.published_date) as published
                    FROM
                        blobs b
                        INNER JOIN affected_package_handles aph
                            ON aph.blob_id = b.id
                        INNER JOIN vulnerability_handles v
                            ON v.id = aph.vulnerability_id,
                        json_each(json_extract(b.value, '$.ranges')) ranges,
                        json_each(json_extract(ranges.value, '$.fix.detail.references')) refs
                    WHERE v.name != json_extract(refs.value, '$.id')
                )
                GROUP BY advisory
                ;
                """)
                for row in cur.fetchall():
                    record_id = row["advisory"]
                    aliases = row["aliases"]
                    if aliases:
                        aliases = json.loads(aliases)

                    records.append(
                        ProviderRecord(
                            id=record_id,
                            aliases=Aliases.from_list([record_id, *aliases]),
                            published=self._parse_date(row["published"]),
                        ),
                    )

                logging.debug(f"Finish processing {self.name} alias records")

        return records


class GrypeDBExtraCVEs(Provider):
    def __init__(self):
        super().__init__(
            name="Grype DB Extra CVEs",
        )

    def _fetch(self) -> list[ProviderRecord]:
        records = []
        with tempfile.TemporaryDirectory() as tmp:
            logging.debug(f"Start fetching latest {self.name} content to {tmp}")
            os.environ["GRYPE_DB_CACHE_DIR"] = tmp
            execute_command("grype db update")
            logging.debug(f"Finish fetching latest {self.name} content to {tmp}")
            path = os.path.join(tmp, "6/vulnerability.db")
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row # Allows accessing cursor results by column name
                logging.debug(f"Start processing {self.name} alias records")
                cur = conn.cursor()
                # For now just limit to the identifiers we won't currently pull elsewhere due to
                # lack of convenient bulk downloads: chainguard libs, oracle linux, and amazon linux
                cur.execute("""
                SELECT DISTINCT
                    v.name as id
                FROM
                    vulnerability_handles v
                WHERE
                    v.provider_id <> "nvd"
                    and v.name like "CVE-____-%"
                    and v.name not in (
                        select name from vulnerability_handles where provider_id = 'nvd'
                    )
                ;
                """)
                for row in cur.fetchall():
                    cve_id = row["id"]
                    components = cve_id.split("-")
                    # There are a few weird CVE entries that should not be allocated, these
                    # checks should eliminate them
                    if len(components) != 3:
                        continue
                    try:
                        year = int(components[1])
                    except:  # noqa: E722, S112
                        continue

                    published = datetime(year=year, day=1, month=1, tzinfo=UTC)
                    records.append(
                        ProviderRecord(
                            id=cve_id,
                            aliases=Aliases.from_list([cve_id]),
                            published=published,
                        ),
                    )

                logging.debug(f"Finish processing {self.name} alias records")

        return records
