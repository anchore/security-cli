import logging

from anchore_security_cli.index.base import SQLiteIndex


def render(input_path: str, store: SQLiteIndex):
    logging.info(f"Start rendering security identifiers index at {store.db_path} from store at {input_path}")
    store.render(input_path)
    logging.info(f"Finish rendering security identifiers index at {store.db_path} from store at {input_path}")
