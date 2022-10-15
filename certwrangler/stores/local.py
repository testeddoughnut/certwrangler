import hashlib
import json
import logging
import pathlib
from dataclasses import field
from marshmallow_dataclass import dataclass
from certwrangler.models import (
    Account,
    AccountState,
    Cert,
    CertState,
    Store,
    StoreDriver,
)
from certwrangler.types import Path

log = logging.getLogger(__name__)


@dataclass
class LocalStore(StoreDriver):
    """Local Storage"""

    path: Path = field(metadata={"required": True})

    def initialize(self, parent: Store) -> None:
        self.parent = parent
        self.accounts_path = self.path.joinpath("accounts")
        self.certs_path = self.path.joinpath("certs")
        if not self.path.exists():
            log.info(f"Creating directory '{self.path}' for store '{self.parent.name}'")
            self.path.mkdir()
        if not self.accounts_path.exists():
            log.info(
                f"Creating directory '{self.accounts_path}' for store '{self.parent.name}'"
            )
            self.accounts_path.mkdir()
        if not self.certs_path.exists():
            log.info(
                f"Creating directory '{self.certs_path}' for store '{self.parent.name}'"
            )
            self.certs_path.mkdir()

    def load_account(self, account: Account) -> AccountState:
        account_state_path = self.accounts_path.joinpath(f"{account.name}.json")
        if not account_state_path.exists():
            return None
        with open(account_state_path, "r") as file_handler:
            account_state = AccountState.Schema().load(json.load(file_handler))
        return account_state

    def save_account(self, account: Account) -> None:
        account_state_path = self.accounts_path.joinpath(f"{account.name}.json")
        with open(account_state_path, "w") as file_handler:
            json.dump(
                account.state.Schema().dump(account.state), file_handler, indent=4
            )
        log.debug(f"Account '{account.name}' state saved to '{account_state_path}'")

    def load_cert(self, cert: Cert) -> CertState:
        cert_state_path = self.certs_path.joinpath(f"{cert.name}.json")
        if not cert_state_path.exists():
            return None
        with open(cert_state_path, "r") as file_handler:
            cert_state = CertState.Schema().load(json.load(file_handler))
        return cert_state

    def save_cert(self, cert: Cert) -> None:
        cert_state_path = self.certs_path.joinpath(f"{cert.name}.json")
        with open(cert_state_path, "w") as file_handler:
            json.dump(cert.state.Schema().dump(cert.state), file_handler, indent=4)
        log.debug(f"Cert '{cert.name}' state saved to '{cert_state_path}'")
        if cert.state.key:
            # Update the key if needed
            cert_key_path = self.certs_path.joinpath(f"{cert.name}.key")
            state_contents = cert.state.Schema().dump(cert.state)["key"]
            if self._get_digest(state_contents) != self._get_digest(cert_key_path):
                with open(cert_key_path, "w") as file_handler:
                    file_handler.write(state_contents)
                log.info(f"Cert '{cert.name}' key saved to '{cert_key_path}'")
        if cert.state.cert:
            # Update the cert if needed
            cert_path = self.certs_path.joinpath(f"{cert.name}.crt")
            state_contents = cert.state.Schema().dump(cert.state)["cert"]
            if self._get_digest(state_contents) != self._get_digest(cert_path):
                with open(cert_path, "w") as file_handler:
                    file_handler.write(state_contents)
                log.info(f"Cert '{cert.name}' cert saved to '{cert_path}'")

    def _get_digest(self, obj: str | pathlib.Path) -> str:
        if isinstance(obj, str):
            return hashlib.sha256(obj.encode()).hexdigest()
        if not obj.exists():
            return ""
        with open(obj, "r") as file_handler:
            return hashlib.sha256(
                "".join(file_handler.readlines()).encode()
            ).hexdigest()
