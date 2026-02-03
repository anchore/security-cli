
import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.deployment import DeploymentEnvironment
from anchore_security_cli.index.publisher import publish
from anchore_security_cli.index.renderer import render
from anchore_security_cli.vuln_index.spec.sqlite import SQLiteIndex


@click.group(name="spec")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="render", help="Render the Anchore vulnerability index spec sqlite for publication")
@click.option("--data-path", help="Path to the root of the existing security identifier dataset", required=True)
@click.option("--output", "-o", help="Path to where the index should be rendered", required=True)
@click.pass_obj
def index_render(cfg: Application, data_path: str, output: str) -> None:
    render(data_path, store=SQLiteIndex(output))

@group.command(name="publish", help="Publish the Anchore vulnerability index spec sqlite")
@click.option(
    "--deploy-to",
    type=click.Choice(DeploymentEnvironment, case_sensitive=False),
    help="Deployment environment",
    required=True,
)
@click.option("--index-dir", help="Path to the rendered index directory", required=True)
@click.pass_obj
def index_publish(cfg: Application, deploy_to: DeploymentEnvironment, index_dir: str) -> None:
    publish(index_dir, deploy_to)
