import importlib
import logging
import os
import pathlib
import signal
import sys
import time
from functools import partial
import click
import yaml
from marshmallow import ValidationError

from certwrangler.reconcilers import reconcile_all
from certwrangler.models import Config


XDG_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
XDG_DATA_HOME = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")


log = logging.getLogger(__name__)


def _load_config(ctx: click.Context, initialize: bool = False) -> None:
    config_file = ctx.obj["config_path"]
    try:
        with open(config_file, "r") as file_handler:
            ctx.obj["config"] = Config.Schema().load(
                yaml.load(file_handler, Loader=yaml.FullLoader)
            )
    except (FileNotFoundError, ValidationError) as error:
        log.fatal(f"Failure loading config: {error}")
        ctx.exit(1)
    if initialize:
        ctx.obj["config"].initialize(ctx.obj["state_path"])


def _configure_logging(log_level) -> None:
    # First configure the application logger.
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s: %(levelname)s [%(name)s, %(funcName)s(), line %(lineno)d] - %(message)s"
        )
    )
    for logger in ["acme", "certwrangler"]:
        _logger = logging.getLogger(logger)
        _logger.addHandler(log_handler)
        _logger.setLevel(log_level)


click_option = partial(  # pylint: disable=invalid-name
    click.option, show_default=True, show_envvar=True
)


@click.group()
@click.version_option()
@click_option(
    "--config",
    "-c",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
    default=f"{XDG_CONFIG_HOME}/certwrangler.yaml",
    envvar="CERTWRANGLER_CONFIG",
    help="Config file for certwrangler.",
    show_default=True,
    show_envvar=True,
)
@click_option(
    "--state",
    "-s",
    type=click.Path(file_okay=False, path_type=pathlib.Path),
    default=f"{XDG_DATA_HOME}/certwrangler",
    envvar="CERTWRANGLER_STATE_DIR",
    help="State directory for certwrangler.",
    show_default=True,
    show_envvar=True,
)
@click_option(
    "--log-level",
    "-l",
    type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]),
    default="INFO",
    envvar="CERTWRANGLER_LOG_LEVEL",
    help="Logging level for certwrangler.",
    show_default=True,
    show_envvar=True,
)
@click.pass_context
def cli(ctx, config, state, log_level) -> None:
    """The certwrangler management cli."""

    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["state_path"] = state
    ctx.obj["log_level"] = log_level
    _configure_logging(ctx.obj["log_level"])


@cli.command()
@click_option(
    "--sleep",
    "-s",
    type=click.INT,
    default=60,
    envvar="CERTWRANGLER_SLEEP",
    help="Sleep time in seconds between each loop.",
)
@click.pass_context
def daemon(ctx, sleep) -> None:
    """Run certwrangler in daemon mode."""

    _load_config(ctx, initialize=True)
    ctx.obj["reload"] = False

    def reload_handler(*args) -> None:
        log.info("Caught SIGHUP, will reload at start of next loop.")
        ctx.obj["reload"] = True

    signal.signal(signal.SIGHUP, reload_handler)

    try:
        while True:
            if ctx.obj["reload"]:
                _load_config(ctx, initialize=True)
                ctx.obj["reload"] = False
            reconcile_all(ctx.obj["config"])
            log.info(f"Sleeping {sleep} seconds.")
            time.sleep(sleep)
    except KeyboardInterrupt:
        log.info("Stopping certwrangler...")


@cli.command()
@click.pass_context
def check_config(ctx) -> None:
    """Check that the provided config is valid."""

    _load_config(ctx)
    click.secho(" ✅ - Config file loaded successfully.", fg="green")


@cli.command()
@click.pass_context
def run(ctx) -> None:
    """Run a single reconcile loop of certwrangler."""

    _load_config(ctx, initialize=True)
    reconcile_all(ctx.obj["config"])


if importlib.util.find_spec("IPython"):
    # Add the super secret dev shell.

    @cli.command(context_settings={"ignore_unknown_options": True})
    @click.argument("ipython_args", nargs=-1, type=click.UNPROCESSED)
    @click.pass_context
    def dev_shell(ctx, ipython_args) -> None:
        """Open an IPython shell with a certwrangler context."""

        _load_config(ctx)

        import IPython
        from IPython.terminal.ipapp import load_default_config
        from certwrangler import controllers, dns, models, reconcilers

        user_ns = {
            "config": ctx.obj["config"],
            "config_path": ctx.obj["config_path"],
            "state_path": ctx.obj["state_path"],
            "controllers": controllers,
            "dns": dns,
            "models": models,
            "reconcilers": reconcilers,
        }
        avail_vars = "\n  ".join(user_ns.keys())
        ipython_config = load_default_config()
        ipython_config.TerminalInteractiveShell.banner1 = (
            f"Welcome to certwrangler's development shell!\n"
            f"  Python {sys.version} on {sys.platform}.\n"
            f"Loaded certwrangler variables:\n  {avail_vars}\n"
            f"Config loaded but not initialized, initialize with:\n"
            f"  config.initialize(state_path)\n"
        )

        IPython.start_ipython(
            argv=ipython_args,
            user_ns=user_ns,
            config=ipython_config,
        )


def main() -> None:
    cli()
