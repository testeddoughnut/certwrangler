import logging
from certwrangler.controllers import AccountController, CertController
from certwrangler.models import Config, Account, Cert


log = logging.getLogger(__name__)


def reconcile_all(config: Config) -> None:
    """Reconcile all objects in the config."""

    log.info("Starting reconciliation...")
    for account in config.accounts.values():
        reconcile_account(account)
    for cert in config.certs.values():
        reconcile_cert(cert)
    log.info("Finished reconciliation.")


def reconcile_account(account: Account) -> None:
    """
    Ensure an account is created on the remote acme server and that
    our contact info is correct.
    """

    log.info(f"Reconciling account '{account.name}'...")
    controller = AccountController(account)
    if not account.state.key:
        log.info(f"No key found for account '{account.name}', creating...")
        controller.create_key()
    if not account.state.registration:
        log.info(f"No registration found for account '{account.name}', registering...")
        controller.register()
    if account.state.key_size != account.key_size:
        log.info(f"Updating key for account '{account.name}'...")
        controller.change_key()
    if sorted(list(account.state.registration.body.emails)) != sorted(account.emails):
        log.info(f"Updating emails on account '{account.name}'...")
        controller.update_contacts()
    log.info(f"Finished reconciling account '{account.name}'.")


def reconcile_cert(cert: Cert) -> None:
    """
    Ensure a cert is up to date.
    """

    log.info(f"Reconciling cert '{cert.name}'...")
    controller = CertController(cert)
    if not cert.state.key:
        log.info(f"No key found for cert '{cert.name}', creating...")
        controller.create_key()
    if cert.state.order:
        log.info(f"Open order found for cert '{cert.name}', processing...")
        controller.process_order()
    elif not cert.state.cert:
        log.info(f"No cert found for cert '{cert.name}', submitting order...")
        controller.create_order()
    elif cert.needs_renewal:
        log.info(f"Cert '{cert.name}' needs renewal, renewing...")
        controller.create_order()
    else:
        # Just make sure we're published to all of our stores.
        cert.publish()
    log.info(f"Finished reconciling cert '{cert.name}'.")
