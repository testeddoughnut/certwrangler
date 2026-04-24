import datetime

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from certwrangler.exceptions import ControllerError
from certwrangler.models import AccountStatus, CertStatus
from certwrangler.reconcilers import (
    _needs_key_change,
    _needs_renewal,
    reconcile_account,
    reconcile_all,
    reconcile_cert,
)


def test_reconcile_account_no_account_state(mocker, account):
    account.state.key_size = account.key_size
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert account.state.status == AccountStatus.new
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.create_key.assert_called_once()
    mock_account_controller.register.assert_called_once()
    assert account.state.status == AccountStatus.active


def test_reconcile_account_change_key(mocker, account, account_state):
    account_state.key_size = 128
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.change_key.assert_called_once()
    assert mock_account_controller.create_key.call_args_list == []


def test_reconcile_account_update_contacts(mocker, account, account_state):
    account.emails.append("test@example.com")
    mock_account_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is True
    mock_account_controller.update_contacts.assert_called_once()


def test_reconcile_account_failure(mocker, account, caplog):
    mock_account_controller = mocker.MagicMock()
    mock_account_controller.create_key = mocker.MagicMock(
        side_effect=ControllerError("Something broke")
    )
    mocker.patch(
        "certwrangler.reconcilers.AccountController",
        return_value=mock_account_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_account(account, mock_state_manager) is False
    assert "Failed to reconcile account" in caplog.text
    assert account.state.status == AccountStatus.new


def test_reconcile_cert_no_key(mocker, cert):
    mock_cert_controller = mocker.MagicMock()

    def _create_mock_key():
        cert.state.key = "dummy key"
        cert.state.key_size = cert.key_size
        cert.state.key_algorithm = cert.key_algorithm
        cert.state.key_curve = cert.key_curve

    def _create_mock_cert():
        cert.state.cert = "dummy cert"

    mock_cert_controller.create_key.side_effect = _create_mock_key
    mock_cert_controller.create_order.side_effect = _create_mock_cert
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert cert.state.status == CertStatus.new
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_called_once()
    mock_cert_controller.create_order.assert_called_once()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()
    assert cert.state.status == CertStatus.active


def test_reconcile_cert_key_change(mocker, cert, cert_state):
    cert.key_size = 128
    mock_cert_controller = mocker.MagicMock()

    def _create_mock_key():
        cert.state.key = "dummy key"
        cert.state.key_size = cert.key_size
        cert.state.key_algorithm = cert.key_algorithm
        cert.state.key_curve = cert.key_curve
        # Real CertController.create_key() replaces entire CertState,
        # clearing cert, chain, order, csr, url
        cert.state.cert = None
        cert.state.order = None
        cert.state.chain = None

    def _create_mock_cert():
        cert.state.cert = "dummy cert"

    mock_cert_controller.create_key.side_effect = _create_mock_key
    mock_cert_controller.create_order.side_effect = _create_mock_cert
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_called_once()
    mock_cert_controller.create_order.assert_called_once()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()


def test_reconcile_process_order(mocker, cert, cert_state):
    cert.key_size = cert.state.key_size
    cert.state.order = mocker.MagicMock()
    mock_cert_controller = mocker.MagicMock()
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_not_called()
    mock_cert_controller.create_order.assert_not_called()
    mock_cert_controller.process_order.assert_called_once()


def test_reconcile_cert_renewal(mocker, cert, cert_state):
    cert.key_size = cert.state.key_size
    cert.alt_names = ["example.com", "test.example.com"]
    mock_cert_controller = mocker.MagicMock()

    def mock_create_order():
        assert cert.state.status == CertStatus.renewing

    mock_cert_controller.create_order.side_effect = mock_create_order
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert cert.state.status == CertStatus.active
    assert reconcile_cert(cert, mock_state_manager) is True
    mock_cert_controller.create_key.assert_not_called()
    mock_cert_controller.create_order.assert_called_once()
    mock_cert_controller.process_order.assert_not_called()
    mock_cert_controller.publish.assert_called_once()
    assert cert.state.status == CertStatus.active


def test_reconcile_cert_failure(mocker, cert, caplog):
    mock_cert_controller = mocker.MagicMock()
    mock_cert_controller.create_key = mocker.MagicMock(
        side_effect=ControllerError("Something broke")
    )
    mocker.patch(
        "certwrangler.reconcilers.CertController",
        return_value=mock_cert_controller,
    )
    mock_state_manager = mocker.MagicMock()
    assert reconcile_cert(cert, mock_state_manager) is False
    assert "Failed to reconcile cert" in caplog.text


def test_reconcile_all_account_failure(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=False,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=True,
    )
    assert reconcile_all(config) is False
    assert "Finished reconciliation with errors." in caplog.text


def test_reconcile_all_cert_failure(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=True,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=False,
    )
    assert reconcile_all(config) is False
    assert "Finished reconciliation with errors." in caplog.text


def test_reconcile_all_successful(mocker, config, caplog):
    mocker.patch(
        "certwrangler.reconcilers.reconcile_account",
        return_value=True,
    )
    mocker.patch(
        "certwrangler.reconcilers.reconcile_cert",
        return_value=True,
    )
    assert reconcile_all(config) is True
    assert "Finished reconciliation." in caplog.text


class Test__needs_renewal:
    """
    Tests for _needs_renewal() cert renewal checks.
    """

    def test_no_key(self, cert, cert_state):
        cert.state.key = None
        assert _needs_renewal(cert) is True

    def test_no_cert(self, cert, cert_state):
        cert.state.cert = None
        assert _needs_renewal(cert) is True

    def test_expiry_threshold(self, mocker, cert, cert_state):
        short_expiry = mocker.PropertyMock(
            return_value=cert.renewal_threshold - datetime.timedelta(days=1)
        )
        mocker.patch.object(type(cert), "time_left", short_expiry)
        assert _needs_renewal(cert) is True

    def test_common_name_changed(self, cert, cert_state):
        cert.common_name = "changed.example.com"
        assert _needs_renewal(cert) is True

    def test_alt_names_changed(self, cert, cert_state):
        cert.alt_names = ["new.example.com"]
        assert _needs_renewal(cert) is True

    def test_key_mismatch(self, cert, cert_state):
        cert.state.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert _needs_renewal(cert) is True

    def test_no_changes(self, cert, cert_state):
        cert.key_size = cert.state.key_size
        assert _needs_renewal(cert) is False


class Test__needs_key_change:
    """
    Tests for _needs_key_change() key config checks.
    """

    def test_no_key_account(self, account):
        assert _needs_key_change(account) is True

    def test_no_key_cert(self, cert):
        assert _needs_key_change(cert) is True

    def test_algorithm_changed_account(self, account, account_state):
        account.key_algorithm = rsa.RSAPrivateKey
        account_state.key_algorithm = ec.EllipticCurvePrivateKey
        assert _needs_key_change(account) is True

    def test_curve_changed(self, cert, cert_state):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        cert.key_algorithm = ec.EllipticCurvePrivateKey
        cert.key_curve = SECP384R1
        cert.state.key_algorithm = ec.EllipticCurvePrivateKey
        assert _needs_key_change(cert) is True

    def test_size_changed(self, account, account_state):
        account.key_algorithm = rsa.RSAPrivateKey
        account.state.key_algorithm = rsa.RSAPrivateKey
        account.key_size = 4096
        account.state.key_size = 2048
        assert _needs_key_change(account) is True

    def test_no_changes_account(self, account, account_state):
        assert _needs_key_change(account) is False

    def test_no_changes_cert(self, cert, cert_state):
        cert.key_size = cert.state.key_size
        assert _needs_key_change(cert) is False
