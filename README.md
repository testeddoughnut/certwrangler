# Certwrangler

Wrangle you ACME certs.

## Config and state storage

Though it's not a desktop application, Certwrangler adheres to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) for config and state by default. It will load its config from `${XDG_CONFIG_HOME}/certwrangler` (or `~/.config/certwrangler.yaml` if `${XDG_CONFIG_HOME}` is not set) and saves its state to `${XDG_DATA_HOME}/certwrangler` (or `~/.local/share/certwrangler` if `${XDG_DATA_HOME}` is not set). This can be overridden by
providing the option `--config` or the environment variable `${CERTWRANGLER_CONFIG}` for config, and providing the cli option `--state` or the environment variable `${CERTWRANGLER_STATE_DIR}` for state.

## Development

Create a virtual environment, clone the repo, then install with:

```
pip install -e .[dev]
```

Then copy `certwrangler.example.yaml` to `~/.config/certwrangler.yaml` and fill it out with your info.

The documentation for the lexicon solver driver is here:
https://dns-lexicon.readthedocs.io/en/latest/configuration_reference.html

The installation installs the `certwrangler` cli utility for controlling certwrangler:

```
$ certwrangler --help
Usage: certwrangler [OPTIONS] COMMAND [ARGS]...

  The certwrangler management cli.

Options:
  --version                       Show the version and exit.
  -c, --config FILE               Config file for certwrangler.  [env var:
                                  CERTWRANGLER_CONFIG; default:
                                  /home/${your_username}/.config/certwrangler.yaml]
  -s, --state DIRECTORY           State directory for certwrangler.  [env var:
                                  CERTWRANGLER_STATE_DIR; default:
                                  /home/${your_username}/.local/share/certwrangler]
  -l, --log-level [CRITICAL|ERROR|WARNING|INFO|DEBUG]
                                  Logging level for certwrangler.  [env var:
                                  CERTWRANGLER_LOG_LEVEL; default: INFO]
  --help                          Show this message and exit.

Commands:
  check-config  Check that the provided config is valid.
  daemon        Run certwrangler in daemon mode.
  dev-shell     Open an IPython shell with a certwrangler context.
  run           Run a single reconcile loop of certwrangler.
```

If you installed with the `[dev]` extras then you'll also have access to the `dev-shell` sub-command, which provides you with an IPython environment pre-loaded with the various certwrangler modules loaded, which is helpful for playing around with the various types to test out changes:

```
$ certwrangler dev-shell
Welcome to certwrangler's development shell!
  Python 3.10.7 (main, Sep 14 2022, 22:35:07) [GCC 11.3.0] on linux.
Loaded certwrangler variables:
  config
  config_path
  state_path
  controllers
  dns
  models
  reconcilers
Config loaded but not initialized, initialize with:
  config.initialize(state_path)

In [1]:
```
