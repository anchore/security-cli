import os
import sqlite3
import tomllib
from glob import iglob
from itertools import batched
from pathlib import Path

import jsonschema_rs
import orjson
import requests

from anchore_security_cli.identifiers.anchore_id import parse
from anchore_security_cli.index.base import SQLiteIndex as BaseSQLiteIndex
from anchore_security_cli.index.config import IndexConfig
from anchore_security_cli.index.version import IndexVersion


class SchemaValidator:
    def __init__(self, version: IndexVersion) -> None:
        self.schema_version = str(version)
        self.schema_url = f"https://raw.githubusercontent.com/anchore/vulnerability-index-spec-files/refs/heads/main/schema/published/{version!s}.schema.json"
        self._validator = None

    def _retrieve_schema_def(self):
        json_schema = requests.get(self.schema_url, timeout=30).json()
        self._validator = jsonschema_rs.validator_for(json_schema)

    def validate(self, value: bytes):
        if self._validator is None:
            self._retrieve_schema_def()

        self._validator.validate(orjson.loads(value))


class SQLiteIndex(BaseSQLiteIndex):
    """sqlite3-based SQLite store for indexing Anchore vulnerability index spec file data"""

    def __init__(self, store_path: str | Path) -> None:
        super().__init__(
            store_path=store_path,
            config=IndexConfig(
                name="vulnerability-index-specs",
                db_name="vulnerability-index-specs.db",
                format="sqlite",
                version=IndexVersion(model=0,revision=1,addition=0),
            ),
        )
        self.validator = SchemaValidator(self._config.version)

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS `records` (
                `anchore_id` TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
                `year` INTEGER NOT NULL,
                `index` INTEGER NOT NULL,
                `spec` TEXT NOT NULL
            )
        """)

        conn.execute("PRAGMA optimize")  # optimize query planner statistics
        conn.commit()

    def _create_indices(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS `idx_records_year` ON records (`year`)",
        )
        conn.execute("PRAGMA optimize")  # optimize query planner statistics
        conn.commit()

    def _toml_to_json(self, toml_data: dict) -> dict:  # noqa: C901, PLR0912
        record = {
            "schema": {
                "url": self.validator.schema_url,
                "version": self.validator.schema_version,
            },
            "vuln": toml_data["vuln"],
        }

        if "providers" not in record["vuln"]:
            return record

        for _, provider_records in record["vuln"]["providers"].items():
            for provider_record in provider_records:
                if "products" not in provider_record:
                    continue

                for k in ["override", "merge", "drop"]:
                    if k not in provider_record["products"]:
                        continue

                    for _, products in provider_record["products"][k].items():
                        for product in products:
                            if "source" in product:
                                product["sources"] = product.pop("source")

                            if "cpe" in product:
                                product["cpes"] = product.pop("cpe")

                            for status in ["affected", "unaffected", "investigating"]:
                                if status not in product:
                                    continue

                                for entry in product[status]:
                                    if "remediation" in entry:
                                        entry["remediations"] = entry.pop("remediation")

                                        for remediation in entry["remediations"]:
                                            if "patch" in remediation:
                                                remediation["patches"] = remediation.pop("patch")

        return record

    def _render(self, data_path: str, conn: sqlite3.Connection):
        for batch in batched(iglob(os.path.join(data_path, "**/ANCHORE-*.toml"), recursive=True), n=5000, strict=False):
            for file in batch:
                self._logger.trace(f"Start rendering index data for file at {file}")
                with open(file, "rb") as f:
                    toml_data = tomllib.load(f)

                anchore_id = parse(toml_data["vuln"]["id"])
                record = self._toml_to_json(toml_data)
                jsonified = orjson.dumps(record, option=orjson.OPT_SORT_KEYS)
                self.validator.validate(jsonified)

                conn.execute(
                    """
                    INSERT INTO `records` (
                        `anchore_id`, `year`, `index`, `spec`
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(anchore_id),
                        anchore_id.year,
                        anchore_id.index,
                        jsonified,
                    ),
                )
                self._logger.trace(f"Finish rendering index data for file at {file}")
            conn.commit()
