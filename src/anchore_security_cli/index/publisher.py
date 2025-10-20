import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from glob import glob

from anchore_security_cli.deployment import DeploymentEnvironment
from anchore_security_cli.index.config import IndexConfig
from anchore_security_cli.index.source import IndexSource
from anchore_security_cli.index.version import IndexVersion
from anchore_security_cli.sqlite import connect
from anchore_security_cli.utils import execute_command


def get_index_metadata_db_path(path: str) -> str:
    if path.endswith(".db"):
        return path

    sqlite_files = glob(os.path.join(path, "*.db"))
    if not sqlite_files:
        raise ValueError(f"{path} does not contain any sqlite .db files")

    if len(sqlite_files) > 1:
        raise ValueError(f"{path} contains multiple sqlite .db files, please specify the path to the one containing the index metadata")

    return sqlite_files[0]


@dataclass(frozen=True, slots=True)
class IndexMetadata:
    config: IndexConfig
    source: IndexSource
    rendered: datetime

    @classmethod
    def from_sqlite(cls, path: str):
        index_db_path = get_index_metadata_db_path(path)
        db_name = os.path.basename(index_db_path)
        with connect(index_db_path, readonly=True) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM index_metadata")

            r = cursor.fetchone()
            m = IndexMetadata(
                config=IndexConfig(
                    name=r["name"],
                    db_name=db_name,
                    format="sqlite",
                    version=IndexVersion(
                        model=r["model"],
                        revision=r["revision"],
                        addition=r["addition"],
                    ),
                ),
                source=IndexSource(
                    git_repo=r["git_repo"],
                    commit=r["commit"],
                ),
                rendered=datetime.fromisoformat(r["rendered"]),
            )
            cursor.close()
            return m


def publish(index_dir: str, env: DeploymentEnvironment):
    logging.info(f"Start publishing index from {index_dir} to {env}")
    metadata = IndexMetadata.from_sqlite(index_dir)
    with tempfile.TemporaryDirectory() as tmp:
        archive = f"{metadata.config.name}.tar.zst"
        logging.debug(f"Start compressing {index_dir}")
        execute_command(f"tar -C {index_dir} -I'zstd -T0 -11' -cvf {archive} {metadata.config.db_name}", cwd=tmp)
        logging.debug(f"Finish compressing {index_dir}")
        oci_path = os.path.join("ghcr.io/anchore/data", str(env), metadata.config.name, metadata.config.format, f"v{metadata.config.version.model}")
        logging.debug(f"Start uploading archive to {oci_path}")
        cmd = f"""oras push -v --no-tty
        --annotation org.opencontainers.image.source={metadata.source.git_repo}
        --annotation org.opencontainers.image.revision={metadata.source.commit}
        --annotation org.opencontainers.image.licenses=CC0-1.0
        --annotation org.opencontainers.image.created={metadata.rendered.isoformat()}
        {oci_path}:git-{metadata.source.commit},{metadata.rendered.strftime("%Y-%m-%d")},latest
        {archive}
        """
        execute_command(cmd, cwd=tmp)
        logging.debug(f"Finish uploading archive to {oci_path}")

    logging.info(f"Finish publishing index from {index_dir} to {env}")
