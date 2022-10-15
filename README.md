# Certwrangler

Wrangle you ACME certs.

## Development

Create a virtual environment, clone the repo, then install with:

```
pip install -e .[development]
```

Then copy `certwrangler.example.yaml` to `certwrangler.yaml` and fill it out with your info.

The documentation for the lexicon solver driver is here:
https://dns-lexicon.readthedocs.io/en/latest/configuration_reference.html

The installation installs the `certwrangler` cli utility for controlling certwrangler:

```
$ certwrangler --help
Usage: certwrangler [OPTIONS] COMMAND [ARGS]...

  The certwrangler management cli.

Options:
  --config PATH                   Config file for certwrangler.  [env var:
                                  CERTWRANGLER_CONFIG; default:
                                  ./certwrangler.yaml]
  --log-level [CRITICAL|ERROR|WARNING|INFO|DEBUG]
                                  Logging level for certwrangler.  [env var:
                                  CERTWRANGLER_LOG_LEVEL; default: INFO]
  --help                          Show this message and exit.

Commands:
  check-config  Check that the provided config is valid.
  daemon        Run certwrangler in daemon mode.
  run           Run a single reconcile loop of certwrangler.
```
