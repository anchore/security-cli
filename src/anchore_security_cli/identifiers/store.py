import logging
import os
import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from glob import iglob

import tomlkit

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.anchore_id import AnchoreId, parse

# These are the current upstream identifier keys which can cause an anchore id to be allocated
CURRENT_ALLOCATION_ALIAS_KEYS = {"cve", "gcve", "github", "openssf_malicious_packages"}


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    year: int
    aliases: Aliases


class UnsupportedLookupIdentifierError(ValueError):
    def __init__(self, identifier: str):
        super().__init__(f"{identifier} is not yet supported for lookup")


class Store:
    def __init__(self, path: str):
        self._path = path
        self._last_index_per_year: dict[int, int] = {}
        self._lookup_by_alias: dict[str, set[AnchoreId]] = {}
        self._load(path)

    def _process_aliases(
        self,
        anchore_id: AnchoreId,
        aliases: dict[str, list] | dict[str, dict],
    ):
        for k, a in aliases.items():
            # Why not consider the full collection of aliases when doing lookups?  Because some (like an OS
            # advisory record) will be an alias for more than one upstream record and we don't want those
            # getting consolidated into a single Anchore id record.  The latest OSV has a seperate section for
            # these (upstreams), but not many ecosystems are using it yet.  Also, with the way it works today,
            # Anchore records are only allocated for existing CVE, GHSA, and OpenSSF Malicious package records
            # so we only need to currently consider those ids when doing lookups.  I have no doubt there is a less
            # confusing way to make all of this work together, but this seems to work for now.
            if k not in CURRENT_ALLOCATION_ALIAS_KEYS:
                continue

            if isinstance(a, list):
                for i in a:
                    if i not in self._lookup_by_alias:
                        self._lookup_by_alias[i] = set()
                    self._lookup_by_alias[i].add(anchore_id)
            elif isinstance(a, dict):
                continue
                # TODO: support this if we ever support allocating records from some upstream with a nested key
                # self._process_aliases(anchore_id, a)

    def _process(self, data: dict):
        anchore_id = parse(data["security"]["id"])
        logging.trace(f"Processing record for {anchore_id}")
        ids = [anchore_id]

        for d in data["security"].get("duplicates", []):
            ids.append(parse(d))

        for i in ids:
            if i.year not in self._last_index_per_year:
                self._last_index_per_year[i.year] = 0
            self._last_index_per_year[i.year] = max(self._last_index_per_year[i.year], i.index)

        self._process_aliases(anchore_id, data["security"].get("aliases", {}))

    def _get_id_path(self, anchore_id: str | AnchoreId) -> str:
        if isinstance(anchore_id, str):
            anchore_id = parse(anchore_id)
        return os.path.join(self._path, str(anchore_id.year), str(anchore_id.index//1000), f"{anchore_id!s}.toml")

    def _refresh_lookups(self, anchore_id: str | AnchoreId):
        logging.trace(f"Refreshing lookups for {anchore_id}")

        if isinstance(anchore_id, str):
            anchore_id = parse(anchore_id)

        file_path = self._get_id_path(anchore_id)
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
            if data["security"]["id"] != str(anchore_id):
                raise ValueError(f"Inconsistent data at {file_path}")

            self._process(data)

    def _load(self, path: str):
        logging.info(f"Start loading security identifier store from {path}")

        for file in iglob(os.path.join(path, "**/ANCHORE-*.toml"), recursive=True):
            logging.trace(f"Loading file at {file}")
            with open(file, "rb") as f:
                data = tomllib.load(f)
                self._process(data)

        logging.info(f"Finish loading security identifier store from {path}")

    def lookup(self, alternate_id: str) -> set[AnchoreId] | None:
        logging.trace(f"Performing lookup for {alternate_id}")
        anchore_ids = self._lookup_by_alias.get(alternate_id)

        if anchore_ids:
            logging.trace(f"Lookup on {alternate_id} found {anchore_ids}")
        else:
            logging.trace(f"Lookup on {alternate_id} did not find any existing allocated ids")

        return anchore_ids

    def assign(self, r: AllocationRequest) -> AnchoreId:
        logging.debug(f"Start allocating identifier for {r}")
        if r.year not in self._last_index_per_year:
            self._last_index_per_year[r.year] = 0

        self._last_index_per_year[r.year] += 1
        index = self._last_index_per_year[r.year]
        anchore_id = AnchoreId(year=r.year, index=index)
        doc = tomlkit.document()
        doc.append("security", tomlkit.table())
        doc["security"]["id"] = str(anchore_id)
        doc["security"]["allocated"] = datetime.now(tz=UTC)
        doc["security"].append("aliases", tomlkit.table(is_super_table=True))
        for alias_type, aliases in asdict(r.aliases).items():
            if aliases:
                doc["security"]["aliases"][alias_type] = sorted(set(aliases))
                doc["security"]["aliases"][alias_type].multiline(True)

        path = self._get_id_path(anchore_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        if os.path.exists(path):
            raise Exception(f"A file already exists at {path}, assignment aborted")

        with open(path, "w") as f:
            tomlkit.dump(doc, f, sort_keys=False)

        self._refresh_lookups(anchore_id)
        logging.debug(f"Finish allocating identifier for {r}")

    def update(self, anchore_id: AnchoreId, aliases: Aliases):
        logging.debug(f"Start updating record for identifier {anchore_id}")
        path = self._get_id_path(anchore_id)
        if not os.path.exists(path):
            return

        with open(path) as f:
            doc = tomlkit.load(f)

        has_updates = False
        for alias_type, a in asdict(aliases).items():
            if a:
                alias_set = set(a)
                if alias_type not in doc["security"]["aliases"]:
                    doc["security"]["aliases"][alias_type] = sorted(alias_set)
                    doc["security"]["aliases"][alias_type].multiline(True)
                    has_updates = True
                else:
                    original = set(alias_set)
                    alias_set.update(doc["security"]["aliases"][alias_type])
                    if alias_set != original:
                        doc["security"]["aliases"][alias_type] = sorted(alias_set)
                        doc["security"]["aliases"][alias_type].multiline(True)
                        has_updates = True

        if has_updates:
            with open(path, "w") as f:
                logging.trace(f"Start Persisting changes for identifier {anchore_id}")
                tomlkit.dump(doc, f, sort_keys=False)
                logging.trace(f"Finish Persisting changes for identifier {anchore_id}")

            self._refresh_lookups(anchore_id)
        logging.debug(f"Finish updating record for identifier {anchore_id}")

    def validate(self):  # noqa: C901
        logging.info("Start validating store state")
        identifier_counts: dict[str, dict[str, int]] = {}
        validation_errors = set()
        duplicates = set()

        for file in iglob(os.path.join(self._path, "**/ANCHORE-*.toml"), recursive=True):
            with open(file, "rb") as f:
                data = tomllib.load(f)

            identifier = data["security"]["id"]

            for k in CURRENT_ALLOCATION_ALIAS_KEYS:
                if "aliases" not in data["security"]:
                    msg = f"{identifier} failed validation, no upstream aliases detected"
                    logging.warning(msg)
                    validation_errors.add(msg)

                if k in data["security"]["aliases"]:
                    if k not in identifier_counts:
                        identifier_counts[k] = {}

                    for v in data["security"]["aliases"][k]:
                        if v not in identifier_counts[k]:
                            identifier_counts[k][v] = 0
                        identifier_counts[k][v] += 1

                        if identifier_counts[k][v] > 1:
                            logging.warning(f"{identifier} failed validation, duplicates detected for {v}")
                            duplicates.add(v)

        if duplicates:
            validation_errors.add(f"Validation failed, please resolve duplicate allocations for {sorted(duplicates)}")

        if validation_errors:
            raise ValueError(f"Validation failed: {validation_errors}")

        logging.info("Finish validating store state")
