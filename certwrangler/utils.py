import os
import sys
import logging
import yaml
from certwrangler.exceptions import NoConfigFile
from certwrangler.models import Config


def load_config(config_file: str) -> dict:
    if not os.path.exists(config_file):
        raise NoConfigFile(f"File {config_file} does not exist.")
    with open(config_file, "r") as file_handler:
        config = Config.Schema().load(yaml.load(file_handler, Loader=yaml.FullLoader))
    return config


def configure_logging(log_level) -> None:
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
