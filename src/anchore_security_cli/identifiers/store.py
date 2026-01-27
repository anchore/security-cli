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
CURRENT_ALLOCATION_ALIAS_KEYS: set[str] = {"cve", "gcve", "github", "openssf_malicious_packages"}


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    year: int
    aliases: Aliases


@dataclass(frozen=True, slots=True)
class ConsolidationRequest:
    to: str | AnchoreId | None
    records: set[str | AnchoreId]


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

    def _merge_documents(self, to: tomlkit.TOMLDocument, source: tomlkit.TOMLDocument) -> tomlkit.TOMLDocument:
        if "security" not in to or "aliases" not in to["security"]:
            raise ValueError("Invalid merge target")

        if "security" not in source or "aliases" not in source["security"]:
            raise ValueError("Invalid merge source")

        if "duplicates" not in to["security"]:
            to["security"]["duplicates"] = tomlkit.array()

        for k, v in source["security"]["aliases"].items():
            if k not in to["security"]["aliases"]:
                to["security"]["aliases"].append(k, tomlkit.array())
                to["security"]["aliases"][k] = sorted(v)
            else:
                to["security"]["aliases"][k] = sorted(set(v+to["security"]["aliases"][k]))

        to["security"]["duplicates"] = sorted(set(to["security"]["duplicates"] + [source["security"]["id"]] + source["security"].get("duplicates", [])))  # noqa: E501
        return to

    def _consolidate(self, request: ConsolidationRequest):  # noqa: C901, PLR0912
        logging.debug(f"Start consolidating {request.records} to {request.to}")
        records: set[AnchoreId] = set()
        for o in request.records:
            if isinstance(o, AnchoreId):
                records.add(o)
                continue

            if o.startswith("ANCHORE-"):
                records.add(parse(o))
                continue

            anchore_ids = self.lookup(o)
            if not anchore_ids:
                continue

            for i in anchore_ids:
                records.add(i)

        to = request.to
        if not to:
            to = sorted(records)[0]

        if isinstance(to, str):
            if to.startswith("ANCHORE-"):
                to = parse(to)
            else:
                anchore_ids = self.lookup(to)
                if not anchore_ids:
                    raise ValueError(f"No Anchore identifier record associated with {to}")

                if len(anchore_ids) > 1:
                    raise ValueError(f"Multiple Anchore identifiers corresponding to {to}.  The target must resolve to a single Anchore record, use the ANCHORE id to guaranteee this")  # noqa: E501

                to = anchore_ids.pop()

        if to in records:
            records.remove(to)

        consolidation_path = self._get_id_path(to)
        if not os.path.exists(consolidation_path):
            raise ValueError(f"No existing record for consolidation target {to}")

        with open(consolidation_path) as f:
            consolidation_doc = tomlkit.load(f)

        for r in records:
            r_path = self._get_id_path(r)
            if not os.path.exists(r_path):
                raise ValueError(f"No existing record for consolidation source {r}")

            with open(r_path) as f:
                r_doc = tomlkit.load(f)
            consolidation_doc = self._merge_documents(consolidation_doc, r_doc)

        with open(consolidation_path, "w") as f:
            logging.trace(f"Start Persisting changes for identifier {to}")
            tomlkit.dump(consolidation_doc, f, sort_keys=False)
            logging.trace(f"Finish Persisting changes for identifier {to}")

        for r in records:
            os.remove(self._get_id_path(r))

        logging.debug(f"Finish consolidating {request.records} to {request.to}")

    def _generate_consolidation_requests(self) -> list[ConsolidationRequest]:  # noqa: C901
        allocation_identifier_to_anchore_ids: dict[str, dict[str, set[AnchoreId]]] = {}

        for file in iglob(os.path.join(self._path, "**/ANCHORE-*.toml"), recursive=True):
            with open(file, "rb") as f:
                data = tomllib.load(f)

            identifier: AnchoreId = parse(data["security"]["id"])
            if "aliases" not in data["security"]:
                continue

            for k in CURRENT_ALLOCATION_ALIAS_KEYS:
                if k in data["security"]["aliases"]:
                    if k not in allocation_identifier_to_anchore_ids:
                        allocation_identifier_to_anchore_ids[k] = {}

                    for v in data["security"]["aliases"][k]:
                        if v not in allocation_identifier_to_anchore_ids[k]:
                            allocation_identifier_to_anchore_ids[k][v] = set()
                        allocation_identifier_to_anchore_ids[k][v].add(identifier)

        requests: dict[AnchoreId, ConsolidationRequest] = {}
        for alias_mapping in allocation_identifier_to_anchore_ids.values():
            for anchore_record_mapping in alias_mapping.values():
                if len(anchore_record_mapping) > 1:
                    s= sorted(anchore_record_mapping)
                    if s[0] not in requests:
                        requests[s[0]] = ConsolidationRequest(to=s[0], records=set(s[1:]))
                    else:
                        requests[s[0]].records.update(s[1:])

        return list(requests.values())

    def consolidate(self, requests: list[ConsolidationRequest]):
        logging.info("Start record consolidation")
        if not requests:
            requests = self._generate_consolidation_requests()

        if requests:
            for r in requests:
                self._consolidate(r)
        logging.info("Finish record consolidation")

    def validate(self):  # noqa: C901
        logging.info("Start validating store state")
        identifier_counts: dict[str, dict[str, int]] = {}
        validation_errors = set()
        duplicates = set()

        for file in iglob(os.path.join(self._path, "**/ANCHORE-*.toml"), recursive=True):
            with open(file, "rb") as f:
                data = tomllib.load(f)

            identifier = data["security"]["id"]

            if "aliases" not in data["security"]:
                msg = f"{identifier} failed validation, no upstream aliases detected"
                logging.warning(f"{msg}: {data}")
                validation_errors.add(msg)
            else:
                for k in CURRENT_ALLOCATION_ALIAS_KEYS:
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
