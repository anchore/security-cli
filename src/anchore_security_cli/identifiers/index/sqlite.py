import os
import sqlite3
import tomllib
from glob import iglob
from itertools import batched
from pathlib import Path

from anchore_security_cli.identifiers.anchore_id import parse
from anchore_security_cli.index.base import SQLiteIndex as BaseSQLiteIndex
from anchore_security_cli.index.config import IndexConfig
from anchore_security_cli.index.version import IndexVersion


class SQLiteIndex(BaseSQLiteIndex):
    """sqlite3-based SQLite store for indexing Anchore security identifiers and the various upstream aliases"""

    def __init__(self, store_path: str | Path) -> None:
        super().__init__(
            store_path=store_path,
            config=IndexConfig(
                name="security-identifiers",
                db_name="security-identifiers.db",
                format="sqlite",
                version=IndexVersion(model=1,revision=0,addition=0),
            ),
        )

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS `security_identifiers` (
                `anchore_id` TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
                `year` INTEGER NOT NULL,
                `index` INTEGER NOT NULL,
                `allocated` TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS `security_aliases` (
                `anchore_id` TEXT COLLATE NOCASE NOT NULL,
                `alias_provider` TEXT COLLATE NOCASE NOT NULL,
                `alias_id` TEXT COLLATE NOCASE NOT NULL,
                PRIMARY KEY (anchore_id, alias_provider, alias_id)
            )
        """)

        conn.execute("PRAGMA optimize")  # optimize query planner statistics
        conn.commit()

    def _create_indices(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS `idx_security_identifiers_year` ON security_identifiers (`year`)",
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS `idx_lookup_by_alias` ON security_aliases (`alias_id`)",
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS `idx_lookup_by_provider_and_alias` ON security_aliases (`alias_provider`, `alias_id`)",
        )
        conn.execute("PRAGMA optimize")  # optimize query planner statistics
        conn.commit()


    def _render(self, data_path: str, conn: sqlite3.Connection):
        for batch in batched(iglob(os.path.join(data_path, "**/ANCHORE-*.toml"), recursive=True), n=5000, strict=False):
            for file in batch:
                self._logger.trace(f"Start rendering index data for file at {file}")
                with open(file, "rb") as f:
                    data = tomllib.load(f)

                s = data["security"]
                anchore_id = parse(s["id"])
                conn.execute(
                    """
                    INSERT INTO `security_identifiers` (
                        `anchore_id`, `year`, `index`, `allocated`
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        s["id"],
                        anchore_id.year,
                        anchore_id.index,
                        s["allocated"],
                    ),
                )

                # Always insert an alias record for the `anchore` provider to the record.
                # This gives a single simple lookup mechanism for indexing into the `security_identifiers`
                # table given any id.
                conn.execute(
                    """
                    INSERT INTO `security_aliases` (
                        `anchore_id`, `alias_provider`, `alias_id`
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        s["id"],
                        "anchore",
                        s["id"],
                    ),
                )

                for duplicate in s.get("duplicates", []):
                    if duplicate == s["id"]:
                        self._logger.warning(f"Unnecessary duplicate: {duplicate}")
                        continue

                    conn.execute(
                        """
                        INSERT INTO `security_aliases` (
                            `anchore_id`, `alias_provider`, `alias_id`
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            s["id"],
                            "anchore",
                            duplicate,
                        ),
                    )

                for provider, aliases in s.get("aliases", {}).items():
                    for alias in aliases:
                        conn.execute(
                            """
                            INSERT INTO `security_aliases` (
                                `anchore_id`, `alias_provider`, `alias_id`
                            ) VALUES (?, ?, ?)
                            """,
                            (
                                s["id"],
                                provider,
                                alias,
                            ),
                        )
                self._logger.trace(f"Finish rendering index data for file at {file}")
            conn.commit()
