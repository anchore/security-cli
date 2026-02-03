import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.cli.vuln_index.spec.commands import group as spec_group


@click.group(name="vuln-index")
@click.pass_obj
def group(_: Application):
    pass

group.add_command(spec_group)
