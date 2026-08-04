import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.snapshots.cve5 import CVE5Snapshotter


@click.group(name="snapshot")
@click.pass_obj
def group(_: Application):
    pass


@group.command(name="cve5", help="Allocate Anchore security identifiers")
@click.option("--repo-root", help="Path to the root of the existing CVE5 dataset git repo", required=True)
@click.option("--commit/--no-commit", default=True)
@click.option("--push/--no-push", default=False)
@click.pass_obj
def cve5_snapshot(cfg: Application, repo_root: str, commit: bool, push: bool) -> None:
    CVE5Snapshotter(repo_root).process(commit=commit, push=push)
