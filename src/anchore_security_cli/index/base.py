import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from anchore_security_cli.index.config import IndexConfig
from anchore_security_cli.index.source import IndexSource
from anchore_security_cli.sqlite import connect
from anchore_security_cli.utils import execute_command


class SQLiteIndex:
    def __init__(self, store_path: str | Path, config: IndexConfig) -> None:
        # convert Path objects to string and add .db extension if not present
        self._config = config
        self._logger = logging.getLogger(self._config.name)
        self._conn = None
        self._db_path = self._construct_store_path(store_path)

    @property
    def db_path(self) -> str:
        return str(self._db_path)

    def _construct_store_path(self, store_path: str | Path) -> Path:
        if isinstance(store_path, str):
            store_path = Path(store_path)

        if store_path.name != self._config.db_name:
            store_path = store_path.joinpath(self._config.db_name)

        return store_path

    def _get_connection(self) -> sqlite3.Connection:
        """create and configure a new SQLite connection"""
        if self._conn:
            return self._conn

        self._conn = connect(self._db_path)
        return self._conn

    def _create_common_tables(self, conn: sqlite3.Connection) -> None:
        self._logger.trace("Start creating common tables")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS `index_metadata` (
                `name` TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
                `git_repo` TEXT NOT NULL,
                `commit` TEXT NOT NULL,
                `rendered` TEXT NOT NULL,
                `model` integer NOT NULL,
                `revision` integer NOT NULL,
                `addition` integer NOT NULL
            )
        """)

        conn.commit()
        self._logger.trace("Finish creating common tables")

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        raise NotImplementedError("This method should be implemented by subclasses")

    def _create_common_indices(self, conn: sqlite3.Connection) -> None:
        pass

    def _create_indices(self, conn: sqlite3.Connection) -> None:
        raise NotImplementedError("This method should be implemented by subclasses")

    def _reset(self) -> None:
        if self._db_path.exists():
            self._db_path.unlink()

    def _pre_render(self, conn: sqlite3.Connection):
        # Just create tables here, create indexes after the rows are inserted as this is significantly faster
        self._create_common_tables(conn)
        self._create_tables(conn)
        conn.execute(
            "PRAGMA cache_size=10000",
        )  # larger cache for better performance

    def _render(self, data_path: str, conn: sqlite3.Connection):
        raise NotImplementedError("This method should be implemented by subclasses")

    def _record_metadata(self, source: IndexSource, conn: sqlite3.Connection):
        conn.execute(
            """
            INSERT INTO `index_metadata` (
                `name`, `git_repo`, `commit`, `rendered`, `model`, `revision`, `addition`
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._config.name,
                source.git_repo,
                source.commit,
                datetime.now(tz=UTC),
                self._config.version.model,
                self._config.version.revision,
                self._config.version.addition,
            ),
        )
        conn.commit()

    def _post_render(self, source, conn: sqlite3.Connection):
        self._record_metadata(source, conn)
        self._create_indices(conn)
        conn.execute("PRAGMA optimize;")
        conn.execute("VACUUM;")
        conn.commit()

    def _determine_git_repo(self, data_path: str) -> str:
        if os.getenv("CI") == "true":
            repo = os.getenv("GITHUB_REPOSITORY")

            if not repo:
                raise ValueError("In CI and GITHUB_REPOSITORY unset")

            return f"https://github.com/{repo}"

        repo = execute_command("git config get remote.origin.url", cwd=data_path)
        if not repo:
            raise ValueError(f"Unable to parse git remote from input at {data_path}")

        repo = repo.strip()

        if repo.startswith("git@github.com:"):
            repo = repo.replace("git@github.com:", "https://github.com/")

        if repo.endswith(".git"):
            repo = repo.rstrip(".git")

        return repo

    def _determine_commit(self, data_path: str) -> str:
        if os.getenv("CI") == "true":
            commit = os.getenv("GITHUB_SHA")

            if not commit:
                raise ValueError("In CI and GITHUB_SHA unset")

            return commit

        commit = execute_command("git rev-parse HEAD", cwd=data_path)
        if not commit:
            raise ValueError(f"Unable to parse git commit from input at {data_path}")

        return commit.strip()

    def _determine_source(self, data_path: str) -> IndexSource:
        if not os.path.exists(data_path):
            raise ValueError(f"{data_path} does not exist")

        return IndexSource(
            git_repo = self._determine_git_repo(data_path),
            commit = self._determine_commit(data_path),
        )

    def render(self, data_path: str):
        source = self._determine_source(data_path)
        self._logger.info(f"Rendering from data path: {data_path} with source {source}")
        self._reset()
        with self._get_connection() as conn:
            self._pre_render(conn)
            self._render(data_path, conn)
            self._post_render(source, conn)

    def close(self) -> None:
        """close database connections"""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        """ensure database connections are closed on object destruction"""
        self.close()
