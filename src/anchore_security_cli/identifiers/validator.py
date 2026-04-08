from anchore_security_cli.identifiers.store import Store
from anchore_security_cli.utils import timer


class Validator:
    def __init__(self, data_path: str):
        self._path = data_path
        self.store: Store = Store(data_path)

    def validate(self):
        with timer("security identifiers store validation"):
            self.store.validate()
