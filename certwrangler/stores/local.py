import hashlib
import logging
import pathlib
from dataclasses import dataclass, field
from marshmallow_dataclass import add_schema
from certwrangler.models import (
    Cert,
    Store,
    StoreDriver,
)
from certwrangler.types import Path

log = logging.getLogger(__name__)


@add_schema
@dataclass
class LocalStore(StoreDriver):
    """Local Storage"""

    path: Path = field(metadata={"required": True})

    def initialize(self, parent: Store) -> None:
        self.parent = parent
        if not self.path.exists():
            log.info(f"Creating directory '{self.path}' for store '{self.parent.name}'")
            self.path.mkdir(parents=True)

    def publish(self, cert: Cert) -> None:
        state_contents = cert.state.Schema().dump(cert.state)
        if cert.state.key:
            # Update the key if needed
            key_path = self.path.joinpath(f"{cert.name}.key")
            if self._get_digest(state_contents["key"]) != self._get_digest(key_path):
                with open(key_path, "w") as file_handler:
                    file_handler.write(state_contents["key"])
                log.info(f"Cert '{cert.name}' key saved to '{key_path}'")
        if cert.state.cert:
            # Update the cert if needed
            cert_path = self.path.joinpath(f"{cert.name}.crt")
            if self._get_digest(state_contents["cert"]) != self._get_digest(cert_path):
                with open(cert_path, "w") as file_handler:
                    file_handler.write(state_contents["cert"])
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
