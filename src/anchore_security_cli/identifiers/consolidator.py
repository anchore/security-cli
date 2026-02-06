
from anchore_security_cli.identifiers.store import ConsolidationRequest, Store
from anchore_security_cli.utils import timer


class Consolidator:
    def __init__(self, data_path: str):
        self._path = data_path
        self.store: Store = Store(data_path)

    def consolidate(self, identifiers: list[str], resolve_to: str):
        with timer("security identifiers consolidation"):
            requests = []
            if identifiers:
                if resolve_to:
                    requests.append(ConsolidationRequest(
                        to = resolve_to,
                        records = identifiers,
                    ))
                else:
                    requests.append(ConsolidationRequest(
                        records = identifiers,
                    ))

            self.store.consolidate(requests)
