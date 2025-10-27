import click

from anchore_security_cli import __name__ as package_name
from anchore_security_cli.cli.config import Application
from anchore_security_cli.cli.id.commands import group as id_group
from anchore_security_cli.cli.legacy.commands import group as legacy_group


@click.option("--verbose", "-v", default=False, help="show logs", count=True)
@click.group(help="Tool for performing various Anchore security data curation tasks ")
@click.version_option(package_name=package_name, message="%(prog)s %(version)s")
@click.pass_context
def root(ctx: click.core.Context, verbose: bool) -> None:
    import logging.config  # noqa: PLC0415

    ctx.obj = Application()
    log_level = ctx.obj.log.level
    if verbose == 1:
        log_level = "DEBUG"
    elif verbose >= 2:
        log_level = "TRACE"

    if ctx.obj.log.slim:
        timestamp_format = ""
        level_format = ""
    else:
        timestamp_format = "%(asctime)s "
        if not ctx.obj.log.show_timestamp:
            timestamp_format = ""

        level_format = "[%(levelname)-5s] "
        if not ctx.obj.log.show_level:
            level_format = ""

    log_format = f"%(log_color)s{timestamp_format}{level_format}%(message)s"

    logging.config.dictConfig(
        {
            "version": 1,
            "formatters": {
                "standard": {
                    "()": "colorlog.ColoredFormatter",  # colored output
                    # [%(module)s.%(funcName)s]
                    "format": log_format,
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                    "log_colors": {
                        "TRACE": "purple",
                        "DEBUG": "cyan",
                        "INFO": "reset",
                        "WARNING": "yellow",
                        "ERROR": "red",
                        "CRITICAL": "red,bg_white",
                    },
                },
            },
            "handlers": {
                "default": {
                    "level": log_level,
                    "formatter": "standard",
                    "class": "colorlog.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "": {  # root logger
                    "handlers": ["default"],
                    "level": log_level,
                },
            },
        },
    )


root.add_command(id_group)
root.add_command(legacy_group)
