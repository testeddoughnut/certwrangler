from __future__ import annotations

import abc
import json
import logging
import pathlib
from datetime import datetime, timedelta
import marshmallow
from dataclasses import field
from importlib.metadata import entry_points
from typing import Type, NoReturn
from cryptography import x509
from cryptography.x509.oid import NameOID
from marshmallow_dataclass import dataclass
from certwrangler.types import (
    RSAKey,
    X509Certificate,
    JWKRSAKey,
    CountryNameOID,
    StateOrProvinceOID,
    LocalityOID,
    OrganizationOID,
    OrganizationalUnitOID,
    Registration,
    Order,
    TimeDelta,
    Domain,
    Email,
    PolyField,
    Url,
)


log = logging.getLogger(__name__)


class BaseDriver:
    """Base driver class."""

    __driver_type__ = None

    @classmethod
    def _load_driver(cls: Type[BaseDriver], driver_name: str) -> BaseDriver:
        matches = entry_points(
            group=f"certwrangler.{cls.__driver_type__}", name=driver_name
        )
        if len(matches) < 1:
            raise ImportError(f"No {cls.__driver_type__} driver named '{driver_name}'")
        if len(matches) > 1:
            raise ImportError(
                f"Multiple {cls.__driver_type__} drivers found named '{driver_name}'"
            )
        return matches[0].load()

    @classmethod
    def schema_factory(
        cls: Type[BaseDriver], object_dict: dict, parent_object_dict: dict
    ) -> marshmallow.Schema:
        driver_name = parent_object_dict.get("driver")
        if not driver_name:
            # just return a dict, it'll yell about driver missing.
            return marshmallow.fields.Dict
        try:
            return cls._load_driver(driver_name).Schema
        except ImportError as e:
            raise marshmallow.ValidationError(e.msg) from e

    @classmethod
    def model_factory(
        cls: Type[BaseDriver], name: str, driver_name: str, config: dict
    ) -> BaseDriver:
        return cls._load_driver(driver_name)(name, **config)


@dataclass
class StoreDriver(BaseDriver, metaclass=abc.ABCMeta):
    """Base class for store drivers."""

    __driver_type__ = "store"

    @abc.abstractmethod
    def initialize(self, parent: Store) -> None:
        raise NotImplemented

    @abc.abstractmethod
    def publish(self, cert: Cert) -> None:
        raise NotImplemented


@dataclass
class SolverDriver(BaseDriver, metaclass=abc.ABCMeta):
    """Base class for ACME challenge solver drivers."""

    __driver_type__ = "solver"

    @abc.abstractmethod
    def initialize(self, parent: Solver) -> None:
        pass

    @abc.abstractmethod
    def create(self, name: str, domain: str, content: str) -> None:
        raise NotImplemented

    @abc.abstractmethod
    def delete(self, name: str, domain: str, content: str) -> None:
        raise NotImplemented


@dataclass
class DriverController:
    """Models that are responsible for controlling a driver."""

    name: str

    def initialize(self) -> None:
        self.driver.initialize(self)
        log.info(
            f"{type(self).__name__} '{self.name}' ({type(self.driver).__name__}) initialized."
        )


@dataclass
class Store(DriverController):
    """Store controller."""

    driver_name: str = field(metadata={"data_key": "driver", "required": True})
    driver: PolyField = field(
        default_factory=dict,
        metadata={
            "data_key": "config",
            "deserialization_schema_selector": StoreDriver.schema_factory,
        },
    )

    def publish(self, cert: Cert) -> NoReturn:
        self.driver.publish(cert)


@dataclass
class Solver(DriverController):
    """ACME solver controller."""

    driver_name: str = field(metadata={"data_key": "driver", "required": True})
    driver: PolyField = field(
        default_factory=dict,
        metadata={
            "data_key": "config",
            "deserialization_schema_selector": SolverDriver.schema_factory,
        },
    )

    def create(self, name: str, domain: str, content: str) -> None:
        return self.driver.create(name, domain, content)

    def delete(self, name: str, domain: str, content: str) -> None:
        return self.driver.delete(name, domain, content)


@dataclass
class Stateful:
    """Models that save their state to the store."""

    name: str

    def __post_init__(self) -> None:
        self.state_subdir = None
        self.state_class = None

    def initialize(self, state_path: pathlib.Path) -> None:
        self.state_path = state_path.joinpath(f"{self.state_subdir}/{self.name}.json")

    def load(self) -> None:
        """Load our state"""

        if not self.state_path.exists():
            self.state = self.state_class()
        else:
            with open(self.state_path, "r") as file_handler:
                self.state = self.state_class.Schema().load(json.load(file_handler))
            log.debug(
                f"{self.__class__.__name__} '{self.name}' state loaded from '{self.state_path}'"
            )

    def save(self) -> None:
        """Save our state"""

        with open(self.state_path, "w") as file_handler:
            json.dump(self.state.Schema().dump(self.state), file_handler, indent=4)
            log.debug(
                f"{self.__class__.__name__} '{self.name}' state saved to '{self.state_path}'"
            )


@dataclass
class AccountState:
    """ACME account state."""

    registration: Registration = None
    key: JWKRSAKey = None
    key_size: int = None


@dataclass
class Account(Stateful):
    """ACME account"""

    emails: list[Email] = field(metadata={"required": True})
    server: Url = "https://acme-v02.api.letsencrypt.org/directory"
    key_size: int = 2048

    def __post_init__(self) -> None:
        self.state_subdir = "accounts"
        self.state_class = AccountState


@dataclass
class Subject:
    """Cert subject."""

    name: str
    country: CountryNameOID = None
    state_or_province: StateOrProvinceOID = None
    locality: LocalityOID = None
    organization: OrganizationOID = None
    organizational_unit: OrganizationalUnitOID = None


@dataclass
class CertState:
    """Managed cert state."""

    url: str = None
    key: RSAKey = None
    key_size: int = None
    cert: X509Certificate = None
    order: Order = None


@dataclass
class Cert(Stateful):
    """Managed cert"""

    common_name: Domain = field(metadata={"required": True})
    stores_names: list[str] = field(
        default_factory=lambda: ["default"], metadata={"data_key": "stores"}
    )
    account_name: str = field(default="default", metadata={"data_key": "account"})
    solver_name: str = field(default="default", metadata={"data_key": "solver"})
    subject_name: str = field(default="default", metadata={"data_key": "subject"})
    alt_names: list[Domain] = field(default_factory=list)
    wait_time: int = 60
    key_size: int = 2048
    follow_cnames: bool = True
    renewal_threshold: TimeDelta = field(
        default=timedelta(days=30), metadata={"precision": "days"}
    )

    def __post_init__(self) -> None:
        self.state_subdir = "certs"
        self.state_class = CertState
        self.account = None
        self.solver = None
        self.stores = []
        self.subject = None

    def publish(self) -> None:
        """Publish our cert and key to the stores."""
        for store in self.stores:
            store.publish(self)

    @marshmallow.validates("stores_names")
    def __validate_unique_stores(self, values) -> NoReturn:
        if len(set(values)) != len(values):
            raise marshmallow.ValidationError("Duplicate stores not allowed.")

    @property
    def time_left(self) -> timedelta | None:
        if not self.state.cert:
            return None
        return self.state.cert.not_valid_after - datetime.now()

    @property
    def needs_renewal(self) -> bool:
        """
        Check if a cert needs to be renewed.

        We specifically don't check for the subject since apparently LE strips that
        out, leaving only the CN.
        """
        if not self.state.cert:
            log.info(f"No cert present in state for cert '{self.name}'.")
            return True
        if self.time_left < self.renewal_threshold:
            log.info(
                f"Cert '{self.name}' expires in '{self.time_left.days}, "
                f"(threshold {self.renewal_threshold.days}).'"
            )
            return True
        state_common_name = self.state.cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value
        if self.common_name != state_common_name:
            log.info(f"Common name changed on cert '{self.name}'.")
            return True
        # This only works for certs with DNS alt names
        alt_names = sorted(
            self.state.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.general_name.DNSName)
        )
        if sorted([self.common_name] + self.alt_names) != alt_names:
            log.info(f"Alternative names changed on cert '{self.name}'.")
            return True
        return False


@dataclass
class Config:
    """Config"""

    accounts: dict[str, Account] = field(metadata={"required": True})
    certs: dict[str, Cert] = field(metadata={"required": True})
    solvers: dict[str, Solver] = field(metadata={"required": True})
    stores: dict[str, Store] = field(metadata={"required": True})
    subjects: dict[str, Subject] = field(metadata={"required": True})

    @marshmallow.pre_load
    def __pre_populate(self, data: dict, **kwargs) -> dict:
        """Pre-populate the config data with some defaults"""
        # First pre-populate an empty default subject if we don't have one
        if not data.get("subjects"):
            data["subjects"] = {}
        if not data["subjects"].get("default"):
            data["subjects"]["default"] = {}
        # Then populate the name of the objects from their keys
        for field_name in self.fields.keys():
            if not data.get(field_name):
                continue
            for key, value in data[field_name].items():
                value["name"] = key
        return data

    def __post_init__(self) -> None:
        """Populate refs on all the certs"""
        errors = {}
        for cert in self.certs.values():
            cert_errors = {}
            # Set account ref
            try:
                cert.account = self.accounts[cert.account_name]
            except KeyError:
                cert_errors["account"] = f"No account named '{cert.account_name}'."
            # Set solver ref
            try:
                cert.solver = self.solvers[cert.solver_name]
            except KeyError:
                cert_errors["solver"] = f"No solver named '{cert.solver_name}'."
            # Set subject ref
            try:
                cert.subject = self.subjects[cert.subject_name]
            except KeyError:
                cert_errors["subject"] = f"No subject named '{cert.subject_name}'."
            # Set store refs
            cert.stores = []
            stores_errors = []
            for store_name in cert.stores_names:
                try:
                    cert.stores.append(self.stores[store_name])
                except KeyError:
                    stores_errors.append(f"No store named '{store_name}'.")
            if stores_errors:
                cert_errors["stores"] = " ".join(stores_errors)
            if cert_errors:
                errors[cert.name] = cert_errors
        if errors:
            raise marshmallow.ValidationError({"certs": errors})

    def initialize(self, state_path: pathlib.Path) -> None:
        """
        Initialize drivers and load state on stateful objects.
        """
        # Make our states directories
        for obj_type in ["accounts", "certs"]:
            obj_states_path = state_path.joinpath(obj_type)
            if not obj_states_path.exists():
                log.info(
                    f"Creating directory '{obj_states_path}' for {obj_type} states."
                )
                obj_states_path.mkdir(parents=True)
        driver_controllers = list(self.stores.values()) + list(self.solvers.values())
        for driver_controller in driver_controllers:
            driver_controller.initialize()
        stateful_objects = list(self.accounts.values()) + list(self.certs.values())
        for stateful_object in stateful_objects:
            stateful_object.initialize(state_path)
            stateful_object.load()
