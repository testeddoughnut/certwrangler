import logging
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from certwrangler.controllers import AccountController, CertController
from certwrangler.metrics import ACCOUNT_METRICS, CERT_METRICS, RECONCILER_DURATION
from certwrangler.models import (
    Account,
    AccountStatus,
    Cert,
    CertStatus,
    Config,
    StateManager,
)

log = logging.getLogger(__name__)


def _needs_renewal(cert: Cert) -> bool:
    """
    Check if a cert needs to be renewed by checking its expiry time is less
    than ``renewal_threshold``, or if it's ``common_name`` or
    ``alternative_names`` changed.

    We specifically don't check for the ``subject`` since apparently LE
    strips that out.

    :returns: A ``bool`` representing if the cert should be renewed.
    """

    if not cert.state.cert:
        log.info(f"No cert present in state for cert '{cert.name}'.")
        return True
    if cert.time_left < cert.renewal_threshold:
        log.info(
            f"Cert '{cert.name}' expires in {cert.time_left.days} days, "
            f"(threshold {cert.renewal_threshold.days})."
        )
        return True
    state_common_name = cert.state.cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value
    if cert.common_name != state_common_name:
        log.info(f"Common name changed on cert '{cert.name}'.")
        return True
    # This only works for certs with DNS alt names
    state_alt_names = sorted(
        cert.state.cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    )
    if set([cert.common_name] + cert.alt_names) != set(state_alt_names):
        log.debug(
            f"'{set([cert.common_name] + cert.alt_names)}' does not equal '{set(state_alt_names)}'."
        )
        log.info(f"Alternative names changed on cert '{cert.name}'.")
        return True
    return False


def _needs_key_change(entity: Union[Account, Cert]) -> bool:
    """
    Checks if the key configuration differs compared to the state.

    :param entity: The :class:`certwrangler.models.Account` or
        :class:`certwrangler.models.Cert` instance to check.

    :returns: A `bool` indicating if the key needs to be changed.
    """

    if entity.state.key is None:
        log.info(f"No key in state for {entity.__class__.__name__} '{entity.name}'.")
        return True
    if entity.key_algorithm != entity.state.key_algorithm:
        log.info(
            f"Configured key_algorithm for {entity.__class__.__name__} '{entity.name}' "
            "differs from state."
        )
        return True
    if (
        entity.key_algorithm == ec.EllipticCurvePrivateKey
        and entity.key_curve != entity.state.key_curve
    ):
        log.info(
            f"Configured key_curve for {entity.__class__.__name__} '{entity.name}' "
            "differs from state."
        )
        return True

    if (
        entity.key_algorithm == rsa.RSAPrivateKey
        and entity.key_size != entity.state.key_size
    ):
        log.info(
            f"Configured key_size for {entity.__class__.__name__} '{entity.name}' "
            "differs from state."
        )
        return True
    return False


@RECONCILER_DURATION.time()
def reconcile_all(config: Config) -> bool:
    """
    Loops through all the accounts and certs in the config and triggers
    reconciliation.

    :param config: The initialized instance of :class:`certwrangler.models.Config`.

    :returns: A `bool` indicating if all object reconciled without error.
    """

    log.info("Starting reconciliation...")
    successful = []
    state_manager = config.state_manager
    for account in config.accounts.values():
        with ACCOUNT_METRICS[account.name].gauges["reconciler_duration"].time():
            successful.append(reconcile_account(account, state_manager))
    for cert in config.certs.values():
        with CERT_METRICS[cert.name].gauges["reconciler_duration"].time():
            successful.append(reconcile_cert(cert, state_manager))
    if all(successful):
        log.info("Finished reconciliation.")
        return True
    else:
        log.error("Finished reconciliation with errors.")
        return False


def reconcile_account(account: Account, state_manager: StateManager) -> bool:
    """
    Reconcile an account's state. This ensures an account is created on the
    remote acme server and that our contact info is correct.

    :param account: The :class:`certwrangler.models.Account` to be reconciled.
    :param state_manager: The :class:`certwrangler.models.StateManager` to be
        used to save changes.

    :returns: A `bool` indicating if the account reconciled without error.
    """

    log.info(f"Reconciling account '{account.name}'...")
    controller = AccountController(account, state_manager)
    try:
        if not account.state.key:
            log.info(f"No key found for account '{account.name}', creating...")
            controller.create_key()
        if not account.state.registration:
            log.info(
                f"No registration found for account '{account.name}', registering..."
            )
            controller.register()
        if _needs_key_change(account):
            log.info(f"Updating key for account '{account.name}'...")
            controller.change_key()
        if account.state.registration and sorted(
            list(account.state.registration.body.emails)
        ) != sorted(account.emails):
            log.info(f"Updating emails on account '{account.name}'...")
            controller.update_contacts()
        account.state.status = AccountStatus.active
        state_manager.save(account)
        log.info(f"Finished reconciling account '{account.name}'.")
        ACCOUNT_METRICS[account.name].counters["reconciler_success"].inc()
        return True
    except Exception as error:
        log.error(f"Failed to reconcile account '{account.name}': {error}")
        ACCOUNT_METRICS[account.name].counters["reconciler_fail"].inc()
        return False


def reconcile_cert(cert: Cert, state_manager: StateManager) -> bool:
    """
    Reconcile a cert's state. This ensures an order for the cert is
    submitted if needed and handles triggering renewals and publishing
    to the stores.

    :param cert: The :class:`certwrangler.models.Cert` to be reconciled.
    :param state_manager: The :class:`certwrangler.models.StateManager` to be
        used to save changes.

    :returns: A `bool` indicating if the cert reconciled without error.
    """

    log.info(f"Reconciling cert '{cert.name}'...")
    controller = CertController(cert, state_manager)
    try:
        if not cert.state.key:
            log.info(f"No key found for cert '{cert.name}', creating...")
            controller.create_key()
        if _needs_key_change(cert):
            log.info(f"Updating key for cert '{cert.name}'...")
            controller.create_key()
        if cert.state.order:
            log.info(f"Open order found for cert '{cert.name}', processing...")
            controller.process_order()
        elif not cert.state.cert:
            log.info(f"No cert found for cert '{cert.name}', submitting order...")
            controller.create_order()
        elif _needs_renewal(cert):
            log.info(f"Cert '{cert.name}' needs renewal, renewing...")
            cert.state.status = CertStatus.renewing
            state_manager.save(cert)
            controller.create_order()
        if not cert.state.order and (cert.state.key and cert.state.cert):
            # make sure we're published to all of our stores.
            controller.publish()
        cert.state.status = CertStatus.active
        state_manager.save(cert)
        log.info(f"Finished reconciling cert '{cert.name}'.")
        CERT_METRICS[cert.name].counters["reconciler_success"].inc()
        return True
    except Exception as error:
        log.error(f"Failed to reconcile cert '{cert.name}': {error}")
        CERT_METRICS[cert.name].counters["reconciler_fail"].inc()
        return False
