from datetime import timedelta
from typing import Any, Dict, Union

from acme import messages
from cryptography import fernet, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from pydantic import BeforeValidator, Field, PlainSerializer, WithJsonSchema
from typing_extensions import Annotated

# Cryptography Types

FernetKey = Annotated[
    fernet.Fernet,
    BeforeValidator(
        lambda value: fernet.Fernet(value) if isinstance(value, str) else value
    ),
    WithJsonSchema({"type": "string"}),
]


_SupportedKeyAlgorithm = Union[
    type[ec.EllipticCurvePrivateKey],
    type[rsa.RSAPrivateKey],
]
_algorithm_map: Dict[str, _SupportedKeyAlgorithm] = {
    "EC": ec.EllipticCurvePrivateKey,
    "RSA": rsa.RSAPrivateKey,
}
_algorithm_map_inverse: Dict[_SupportedKeyAlgorithm, str] = {
    v: k for k, v in _algorithm_map.items()
}


def _algorithm_loader(
    value: Union[str, _SupportedKeyAlgorithm],
) -> _SupportedKeyAlgorithm:
    """
    Deserializes a string representation of a key algorithm to the actual key type.
    Returns the appropriate cryptography private key class.
    """
    if isinstance(value, type) and value in _algorithm_map.values():
        return value
    if isinstance(value, str) and value in _algorithm_map:
        return _algorithm_map[value]
    raise ValueError(
        f"Unsupported algorithm: {value}. "
        f"Supported algorithms: {', '.join(_algorithm_map.keys())}"
    )


KeyAlgorithm = Annotated[
    _SupportedKeyAlgorithm,
    BeforeValidator(_algorithm_loader),
    PlainSerializer(lambda value: _algorithm_map_inverse[value]),
    WithJsonSchema({"type": "string", "enum": list(_algorithm_map.keys())}),
]


_SupportedKeyCurve = Union[
    type[ec.SECP256R1],
    type[ec.SECP384R1],
    type[ec.SECP521R1],
]

_curve_map: Dict[str, _SupportedKeyCurve] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}
_curve_map_inverse: Dict[_SupportedKeyCurve, str] = {
    v: k for k, v in _curve_map.items()
}


def _curve_loader(value: Union[str, _SupportedKeyCurve]) -> _SupportedKeyCurve:
    """
    Deserializes a string representation of an elliptic curve to the actual curve object.
    """
    if isinstance(value, type) and value in _curve_map.values():
        return value
    if isinstance(value, str) and value in _curve_map:
        return _curve_map[value]
    raise ValueError(
        f"Unsupported curve: {value}. Supported curves: {', '.join(_curve_map.keys())}"
    )


KeyCurve = Annotated[
    _SupportedKeyCurve,
    BeforeValidator(_curve_loader),
    PlainSerializer(lambda value: _curve_map_inverse[value]),
    WithJsonSchema({"type": "string", "enum": list(_curve_map.keys())}),
]


def _private_key_loader(
    value: Union[str, Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]],
) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
    """
    Load and validate the private key.
    """
    if isinstance(value, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
        return value
    loaded_value = serialization.load_pem_private_key(value.encode(), password=None)
    if not isinstance(loaded_value, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
        raise ValueError(
            f"Unsupported private key type: {type(loaded_value)}. "
            "Supported types: RSA or ECDSA."
        )
    return loaded_value


PrivateKey = Annotated[
    Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    BeforeValidator(_private_key_loader),
    PlainSerializer(
        lambda value: value.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


X509Certificate = Annotated[
    x509.Certificate,
    BeforeValidator(
        lambda value: (
            x509.load_pem_x509_certificate(value.encode())
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(
        lambda value: value.public_bytes(serialization.Encoding.PEM).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


X509CSR = Annotated[
    x509.CertificateSigningRequest,
    BeforeValidator(
        lambda value: (
            x509.load_pem_x509_csr(value.encode()) if isinstance(value, str) else value
        ),
    ),
    PlainSerializer(
        lambda value: value.public_bytes(serialization.Encoding.PEM).decode()
    ),
    WithJsonSchema({"type": "string"}),
]


# x509 OIDs


CountryNameOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.COUNTRY_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


StateOrProvinceOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]

LocalityOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.LOCALITY_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


OrganizationOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


OrganizationalUnitOID = Annotated[
    x509.NameAttribute,
    BeforeValidator(
        lambda value: (
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value)
            if isinstance(value, str)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.value),
    WithJsonSchema({"type": "string"}),
]


# ACME Types


Registration = Annotated[
    messages.RegistrationResource,
    BeforeValidator(
        lambda value: (
            messages.RegistrationResource.from_json(value)
            if isinstance(value, dict)
            else value
        ),
    ),
    PlainSerializer(lambda value: value.to_json()),
    WithJsonSchema({"type": "object"}),
]


def _order_loader(
    value: Union[Dict[str, Any], messages.OrderResource],
) -> messages.OrderResource:
    """
    Deserializes a json representation of :class:`acme.messages.OrderResource`,
    including casting its sub-keys to the types it expects and deserializing
    any embedded :class:`acme.messages.AuthorizationResource` instances.
    """
    if isinstance(value, messages.OrderResource):
        return value
    body = messages.Order.from_json(value["body"])
    uri = value["uri"]
    csr_pem = bytes(value["csr_pem"], encoding="utf-8")
    fullchain_pem = value["fullchain_pem"] if value.get("fullchain_pem") else None
    authorizations = [
        messages.AuthorizationResource.from_json(auth)
        for auth in value["authorizations"]
    ]
    return messages.OrderResource(
        body=body,
        uri=uri,
        authorizations=authorizations,
        csr_pem=csr_pem,
        fullchain_pem=fullchain_pem,
    )


Order = Annotated[
    messages.OrderResource,
    BeforeValidator(_order_loader),
    PlainSerializer(lambda value: value.to_json()),
    WithJsonSchema({"type": "object"}),
]


# Generic types

Domain = Annotated[
    str,
    Field(
        # taken from https://github.com/python-validators/validators/blob/0.20.0/validators/domain.py#L5-L10
        pattern=r"^(?:(\*\.|[a-zA-Z0-9])"  # First character of the domain (including wildcard)
        r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
        r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
        r"[A-Za-z]$"
    ),
]

Days = Annotated[
    timedelta,
    BeforeValidator(
        lambda value: timedelta(days=value) if isinstance(value, int) else value,
    ),
    PlainSerializer(lambda value: value.days),
]
