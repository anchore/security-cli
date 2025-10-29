
import click

from anchore_security_cli.cli.config import Application
from anchore_security_cli.legacy.cve5 import generate


@click.group(name="cve5")
@click.pass_obj
def group(_: Application):
    pass

@group.command(name="generate", help="Generate legacy CVE 5 ADP style files from Anchore vulnerability spec files")
@click.option("--spec-path", help="Path to the root of the existing Anchore vulnerability spec files", required=True)
@click.option("--output", "-o", help="Path to the root of the legacy CVE 5 datastore", required=True)
@click.pass_obj
def cve5_generate(cfg: Application, spec_path: str, output: str) -> None:
    generate(spec_path, output)
