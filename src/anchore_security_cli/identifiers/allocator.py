import logging

from anchore_security_cli.identifiers.aliases import Aliases
from anchore_security_cli.identifiers.providers import Providers, fetch_all
from anchore_security_cli.identifiers.providers.provider import ProviderRecord
from anchore_security_cli.identifiers.store import AllocationRequest, Store


class Allocator:
    def __init__(self, data_path: str):
        self.data_path = data_path
        self.store: Store | None = None
        self.providers: Providers | None = None

    def refresh_store(self):
        logging.info(f"Start refreshing security identifiers store at {self.data_path}")
        self.store = Store(self.data_path)
        logging.info(f"Finish refreshing security identifiers store at {self.data_path}")

    def refresh_providers(self):
        logging.info("Start refreshing security identifier upstream providers")
        self.providers = fetch_all()
        logging.info("Finish refreshing security identifier upstream providers")

    def _process_record(self, r: ProviderRecord, aliases: list[str]) -> list[str]:
        logging.trace(f"Found the following aliases for {r.id}: {aliases}")
        anchore_ids = set()
        logging.trace(f"Considering the following lookups: {aliases}")
        for a in aliases:
            ids = self.store.lookup(a)
            if ids:
                logging.trace(f"{a} corresponds to {list(ids)}")
                anchore_ids.update(ids)

        aliases_obj = Aliases.from_list(aliases)
        if not anchore_ids:
            self.store.assign(
                AllocationRequest(
                    year=r.published.year,
                    aliases=aliases_obj,
                ),
            )
        else:
            for i in anchore_ids:
                self.store.update(i, aliases_obj)

        return aliases

    def allocate(self, refresh: bool = True):
        logging.info(f"Start allocating ids using existing security identifier data from {self.data_path}")

        if refresh:
            self.refresh_store()
            self.refresh_providers()

        already_processed = set()
        for r in self.providers.cve5.records:
            if r.id in already_processed:
                continue
            logging.debug(f"Processing {r.id}")
            aliases = self.providers.aliases_by_cve(r.id)
            lookups = self._process_record(r, aliases)
            already_processed.update(lookups)

        for r in self.providers.github.records:
            if r.id in already_processed:
                continue
            logging.debug(f"Processing {r.id}")
            aliases = self.providers.aliases_by_ghsa(r.id)
            lookups = self._process_record(r, aliases)
            already_processed.update(lookups)

        for r in self.providers.openssf_malicious_packages.records:
            if r.id in already_processed:
                continue
            logging.debug(f"Processing {r.id}")
            aliases = self.providers.aliases_by_ossf(r.id)
            lookups = self._process_record(r, aliases)
            already_processed.update(lookups)

        self.store.validate()

        logging.info(f"Finish allocating ids using existing security identifier data from {self.data_path}")
