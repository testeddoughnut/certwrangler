from __future__ import annotations

import abc
import logging
from datetime import datetime, timedelta
import marshmallow
from dataclasses import field
from importlib.metadata import entry_points
from typing import Dict, List, Type
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
    def load_account(self, account: Account) -> AccountState:
        raise NotImplemented

    @abc.abstractmethod
    def save_account(self, account: Account) -> None:
        raise NotImplemented

    @abc.abstractmethod
    def load_cert(self, cert: Cert) -> CertState:
        raise NotImplemented

    @abc.abstractmethod
    def save_cert(self, cert: Cert) -> None:
        raise NotImplemented


@dataclass
class SolverDriver(BaseDriver, metaclass=abc.ABCMeta):
    """Base class for ACME challenge solver drivers."""

    __driver_type__ = "solver"

    @abc.abstractmethod
    def initialize(self, parent: Solver) -> None:
        pass

    @abc.abstractmethod
    def create(self, domain: str, content: str, delegated: str = None) -> None:
        raise NotImplemented

    @abc.abstractmethod
    def delete(self, domain: str, content: str, delegated: str = None) -> None:
        raise NotImplemented


@dataclass
class DriverController:
    """Models that are responsible for controlling a driver."""

    def initialize(self) -> None:
        self.driver.initialize(self)
        log.info(
            f"{type(self).__name__} '{self.name}' ({type(self.driver).__name__}) initialized."
        )


@dataclass
class Store(DriverController):
    """Store controller."""

    name: str
    driver_name: str = field(metadata={"data_key": "driver", "required": True})
    driver: PolyField = field(
        default_factory=dict,
        metadata={
            "data_key": "config",
            "deserialization_schema_selector": StoreDriver.schema_factory,
        },
    )

    def load(self, obj: Account | Cert) -> AccountState | CertState:
        if isinstance(obj, Account):
            return self.driver.load_account(obj)
        elif isinstance(obj, Cert):
            return self.driver.load_cert(obj)

    def save(self, obj: Account | Cert) -> None:
        if isinstance(obj, Account):
            self.driver.save_account(obj)
        elif isinstance(obj, Cert):
            self.driver.save_cert(obj)


@dataclass
class Solver(DriverController):
    """ACME solver controller."""

    name: str
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

    __state_class__ = None

    def load(self) -> None:
        """Load our state from the store"""
        self.state = self.store.load(self) or self.__state_class__()

    def save(self) -> None:
        """Save our state to the store"""
        self.store.save(self)


@dataclass
class AccountState:
    """ACME account state."""

    registration: Registration = None
    key: JWKRSAKey = None
    key_size: int = None


@dataclass
class Account(Stateful):
    """ACME account"""

    __state_class__ = AccountState

    name: str
    emails: List[Email] = field(metadata={"required": True})
    store_name: str = field(default="default", metadata={"data_key": "store"})
    server: Url = "https://acme-v02.api.letsencrypt.org/directory"
    key_size: int = 2048


@dataclass
class Subject:
    """Cert subject."""

    name: str = None
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

    __state_class__ = CertState

    name: str
    common_name: Domain = field(metadata={"required": True})
    store_name: str = field(default="default", metadata={"data_key": "store"})
    account_name: str = field(default="default", metadata={"data_key": "account"})
    solver_name: str = field(default="default", metadata={"data_key": "solver"})
    subject_name: str = field(default="default", metadata={"data_key": "subject"})
    alt_names: List[Domain] = field(default_factory=list)
    wait_time: int = 60
    key_size: int = 2048
    follow_cnames: bool = True
    renewal_threshold: TimeDelta = field(
        default=timedelta(days=30), metadata={"precision": "days"}
    )

    @property
    def time_left(self) -> timedelta:
        if not self.state.cert:
            return None
        return self.state.cert.not_valid_after - datetime.now()

    @property
    def needs_renewal(self) -> tuple[bool, list[str]]:
        """
        Check if a cert needs to be renewed.

        We specifically don't check for the subject since apparently LE strips that
        out, leaving only the CN.
        """
        needs_renewal = False
        reasons = []
        if not self.state.cert:
            needs_renewal = True
            reasons.append("No cert present in state.")
        if self.time_left < self.renewal_threshold:
            needs_renewal = True
            reasons.append(
                f"Cert expires in '{self.time_left.days}, (threshold "
                f"{self.renewal_threshold.days}).'"
            )
        state_common_name = self.state.cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value
        if self.common_name != state_common_name:
            needs_renewal = True
            reasons.append("Common name changed.")
        # This only works for certs with DNS alt names
        alt_names = sorted(
            self.state.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.general_name.DNSName)
        )
        if sorted([self.common_name] + self.alt_names) != alt_names:
            needs_renewal = True
            reasons.append("Alt names changed.")
        return needs_renewal, reasons


@dataclass
class Config:
    """Config"""

    accounts: Dict[str, Account] = field(metadata={"required": True})
    certs: Dict[str, Cert] = field(metadata={"required": True})
    solvers: Dict[str, Solver] = field(metadata={"required": True})
    stores: Dict[str, Store] = field(metadata={"required": True})
    subjects: Dict[str, Subject] = field(metadata={"required": True})

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
        """Populate all the refs"""

        def _populate_refs(
            obj_collection_name: str,
            obj_attr: str,
            ref_collection_name: str,
            errors: dict,
        ) -> dict:
            obj_collection = getattr(self, obj_collection_name)
            ref_collection = getattr(self, ref_collection_name)
            collection_errors = {}
            for obj_name, obj in obj_collection.items():
                obj_errors = {}
                name_attr = f"{obj_attr}_name"
                ref_name = getattr(obj, name_attr)
                try:
                    setattr(obj, obj_attr, ref_collection[ref_name])
                except KeyError:
                    obj_errors[obj_attr] = f"No {obj_attr} named '{ref_name}'"
                if obj_errors:
                    collection_errors[obj_name] = obj_errors
            if collection_errors:
                errors[obj_collection_name] = collection_errors

        errors = {}
        _populate_refs("accounts", "store", "stores", errors)
        _populate_refs("certs", "account", "accounts", errors)
        _populate_refs("certs", "solver", "solvers", errors)
        _populate_refs("certs", "store", "stores", errors)
        _populate_refs("certs", "subject", "subjects", errors)
        if errors:
            raise marshmallow.ValidationError(errors)

    def initialize(self) -> None:
        """
        Initialize drivers and load state on stateful objects.
        """
        driver_controllers = list(self.stores.values()) + list(self.solvers.values())
        for driver_controller in driver_controllers:
            driver_controller.initialize()
        stateful_objects = list(self.accounts.values()) + list(self.certs.values())
        for stateful_object in stateful_objects:
            stateful_object.load()
