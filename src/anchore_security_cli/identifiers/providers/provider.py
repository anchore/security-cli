import logging
import pathlib
import shlex
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from dateutil.parser import parse as parse_date

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.utils import execute_command, timer


@dataclass(frozen=True, slots=True)
class ProviderRecord:
    id: str
    published: datetime
    aliases: Aliases


class Provider:
    def __init__(self, name: str):
        self.name = name
        self._records: list[ProviderRecord] = None
        self._lookup_by_cve: dict[str, list[ProviderRecord]] = None
        self._lookup_by_ghsa: dict[str, list[ProviderRecord]] = None
        self._lookup_by_ossf: dict[str, list[ProviderRecord]] = None
        self.fetch()

    @property
    def records(self) -> list[ProviderRecord]:
        return self._records

    def _fetch(self) -> list[ProviderRecord]:
        raise NotImplementedError

    @classmethod
    def _parse_date(cls, d: datetime | str) -> datetime:
        if not d:
            return datetime.now(tz=UTC)

        if not isinstance(d, datetime):
            d = parse_date(d)

        if d.tzinfo is None or d.tzinfo.utcoffset(d) is None:
            d = d.replace(tzinfo=UTC)

        return d

    def _by_cve(self):
        logging.debug(f"Start orienting {self.name} records by CVE")
        self._lookup_by_cve = {}
        for r in self._records:
            for cve in r.aliases.cve:
                if cve not in self._lookup_by_cve:
                    self._lookup_by_cve[cve] = []
                self._lookup_by_cve[cve].append(r)
        logging.debug(f"Finish orienting {self.name} records by CVE: {len(self._lookup_by_cve)} total")

    def _by_ghsa(self):
        logging.debug(f"Start orienting {self.name} records by GHSA")
        self._lookup_by_ghsa = {}
        for r in self._records:
            for ghsa in r.aliases.github:
                if ghsa not in self._lookup_by_ghsa:
                    self._lookup_by_ghsa[ghsa] = []
                self._lookup_by_ghsa[ghsa].append(r)
        logging.debug(f"Finish orienting {self.name} records by GHSA: {len(self._lookup_by_ghsa)} total")

    def _by_ossf(self):
        logging.debug(f"Start orienting {self.name} records by OpenSSF Malicious Package")
        self._lookup_by_ossf = {}
        for r in self._records:
            for ossf in r.aliases.openssf_malicious_packages:
                if ossf not in self._lookup_by_ossf:
                    self._lookup_by_ossf[ossf] = []
                self._lookup_by_ossf[ossf].append(r)
        logging.debug(f"Finish orienting {self.name} records by OpenSSF Malicious Package: {len(self._lookup_by_ossf)} total")

    def _process_records(self):
        logging.debug(f"Start sorting {self.name} records by publish date")
        self._records.sort(key=lambda k: (k.published, k.id))
        logging.debug(f"Finish sorting {self.name} records by publish date")
        self._by_cve()
        self._by_ghsa()
        self._by_ossf()

    def fetch(self) -> list[ProviderRecord]:
        with timer(f"{self.name}: fetch"):
            logging.info(f"Start fetching latest {self.name} records")
            self._records = self._fetch()
            logging.info(f"Finish fetching latest {self.name} records: {len(self._records)} total")
            self._process_records()
            return self._records

    def by_cve(self, cve_id: str) -> list[ProviderRecord] | None:
        return self._lookup_by_cve.get(cve_id)

    def by_ghsa(self, ghsa_id: str) -> list[ProviderRecord] | None:
        return self._lookup_by_ghsa.get(ghsa_id)

    def by_ossf(self, ossf_id: str) -> list[ProviderRecord] | None:
        return self._lookup_by_ossf.get(ossf_id)

class ArchiveProvider(Provider):
    def __init__(self, name: str, url: str):
        self.url = url
        super().__init__(name=name)

    @classmethod
    def _is_supported_archive_extension(cls, extension: str) -> bool:
        return extension.startswith(".tar") or extension == ".zip"

    @classmethod
    def _parse_archive_extension(cls, path: str) -> str:
        return "".join(pathlib.Path(path).suffixes).lower()

    def _process_fetch(self, content_dir: str) -> list[ProviderRecord]:
        raise NotImplementedError

    def _fetch(self) -> list[ProviderRecord]:
        with tempfile.TemporaryDirectory() as tmp:
            with timer(f"{self.name}: downloading from {self.url}"):
                logging.debug(f"Start downloading {self.name} content from {self.url} to {tmp}")
                archive_extension = ArchiveProvider._parse_archive_extension(self.url)
                if not ArchiveProvider._is_supported_archive_extension(archive_extension):
                    raise ValueError(f"Support for {archive_extension} is not currently implemented")
                file = f"content{archive_extension}"
                cmd = f"curl -f -L -o {shlex.quote(file)} -X GET {shlex.quote(self.url)}"
                execute_command(cmd, cwd=tmp)
                logging.debug(f"Finish downloading {self.name} content from {self.url} to {tmp}")

            with timer(f"{self.name}: extracting archive content"):
                logging.debug(f"Start extracting {self.name} content to {tmp}")
                cmd = f"tar -xf {file}"
                if archive_extension == ".zip":
                    cmd = f"unzip {file}"
                execute_command(cmd, cwd=tmp)
                logging.debug(f"Finish extracting {self.name} content to {tmp}")

            with timer(f"{self.name}: processing"):
                logging.debug(f"Start processing {self.name} content from {tmp}")
                records = self._process_fetch(tmp)
                logging.debug(f"Finish processing {self.name} content from {tmp}")
            return records
