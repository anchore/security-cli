import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.cli.id.index.commands import group as index_group
from anchore_security_cli.identifiers.allocator import Allocator


@click.group(name="id")
@click.pass_obj
def group(_: Application):
    pass


@group.command(name="allocate", help="Allocate Anchore security identifiers")
@click.option("--data-path", help="Path to the root of the existing security identifier dataset", required=True)
@click.pass_obj
def allocate_ids(cfg: Application, data_path: str) -> None:
    Allocator(data_path).allocate()

group.add_command(index_group)
