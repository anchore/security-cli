import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.cli.legacy.cve5.commands import group as cve5_group


@click.group(name="legacy")
@click.pass_obj
def group(_: Application):
    pass

group.add_command(cve5_group)
