import logging
import shlex
import subprocess


def execute_command(cmd: str, **kwargs) -> str | bytes | None:
    stderr = kwargs.pop("stderr", subprocess.STDOUT)
    text = kwargs.pop("text", True)

    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=stderr, text=text, **kwargs)
    except subprocess.CalledProcessError as e:
        logging.error(e.output)
        raise e
    return output
