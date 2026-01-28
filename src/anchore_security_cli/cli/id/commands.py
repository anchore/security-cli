import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.cli.id.index.commands import group as index_group
from anchore_security_cli.identifiers.allocator import Allocator
from anchore_security_cli.identifiers.consolidator import Consolidator


@click.group(name="id")
@click.pass_obj
def group(_: Application):
    pass


@group.command(name="allocate", help="Allocate Anchore security identifiers")
@click.option("--data-path", help="Path to the root of the existing security identifier dataset", required=True)
@click.pass_obj
def allocate_ids(cfg: Application, data_path: str) -> None:
    Allocator(data_path).allocate()


@group.command(name="consolidate", help="Consolidate records with duplicate allocating identifiers")
@click.option("--data-path", help="Path to the root of the existing security identifier dataset", required=True)
@click.option("--identifier", multiple=True, help="Identifiers to consolidate (can be aliases)", required=False, default=[])
@click.option("--to", help="Identifier to resolve to (can be an alias, though needs to be unique)", required=False, default=None)
@click.pass_obj
def consolidate_ids(cfg: Application, data_path: str, identifier: list[str], to: str) -> None:
    Consolidator(data_path).consolidate(identifiers=identifier, resolve_to=to)


group.add_command(index_group)
