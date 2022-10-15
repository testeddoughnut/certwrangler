import logging
import signal
import time
from functools import partial
import click
from marshmallow import ValidationError

from certwrangler.reconcilers import reconcile_all
from certwrangler.utils import configure_logging, load_config, NoConfigFile


log = logging.getLogger(__name__)


def _load_config_to_ctx(ctx, initialize: bool = False) -> None:
    log.info(f"Loading config from '{ctx.obj['config_path']}'...")
    try:
        ctx.obj["config"] = load_config(ctx.obj["config_path"])
        if initialize:
            ctx.obj["config"].initialize()
    except (NoConfigFile, ValidationError) as error:
        log.fatal(f"Failure loading config: {error}")
        ctx.exit(1)


click_option = partial(  # pylint: disable=invalid-name
    click.option, show_default=True, show_envvar=True
)


@click.group()
@click_option(
    "--config",
    type=click.Path(),
    default="./certwrangler.yaml",
    envvar="CERTWRANGLER_CONFIG",
    help="Config file for certwrangler.",
    show_default=True,
    show_envvar=True,
)
@click_option(
    "--log-level",
    type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]),
    default="INFO",
    envvar="CERTWRANGLER_LOG_LEVEL",
    help="Logging level for certwrangler.",
    show_default=True,
    show_envvar=True,
)
@click.pass_context
def cli(ctx, config, log_level):
    """The certwrangler management cli."""

    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["log_level"] = log_level
    configure_logging(ctx.obj["log_level"])


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

    _load_config_to_ctx(ctx, initialize=True)
    ctx.obj["reload"] = False

    def reload_handler(*args) -> None:
        log.info("Caught SIGHUP, will reload at start of next loop.")
        ctx.obj["reload"] = True

    signal.signal(signal.SIGHUP, reload_handler)

    try:
        while True:
            if ctx.obj["reload"]:
                _load_config_to_ctx(ctx, initialize=True)
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

    _load_config_to_ctx(ctx)
    click.secho(" ✅ - Config file loaded successfully.", fg="green")


@cli.command()
@click.pass_context
def run(ctx) -> None:
    """Run a single reconcile loop of certwrangler."""

    _load_config_to_ctx(ctx, initialize=True)
    reconcile_all(ctx.obj["config"])


def main() -> None:
    cli()
