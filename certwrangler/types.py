import pathlib
from datetime import timedelta
import marshmallow
import marshmallow_polyfield
import josepy as jose
from acme import messages, challenges
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from marshmallow_dataclass import NewType


### Cryptography Types


class RSAKeyType(marshmallow.fields.Field):
    """RSA Key"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def _deserialize(self, value, *args, **kwargs) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(value.encode(), password=None)


RSAKey = NewType("RSAKey", str, field=RSAKeyType)


class X509CertificateType(marshmallow.fields.Field):
    """x509 Certificate"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.public_bytes(serialization.Encoding.PEM).decode()

    def _deserialize(self, value, *args, **kwargs) -> x509.Certificate:
        return x509.load_pem_x509_certificate(value.encode())


X509Certificate = NewType("X509Certificate", str, field=X509CertificateType)


class JWKRSAKeyType(marshmallow.fields.Field):
    """JSON Web Key RSA"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.to_json()

    def _deserialize(self, value, *args, **kwargs) -> jose.JWKRSA:
        return jose.JWKRSA.from_json(value)


JWKRSAKey = NewType("JWKRSAKey", dict, field=JWKRSAKeyType)


### x509 OIDs


class CountryNameOIDType(marshmallow.fields.Field):
    """x509 Country Name"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.value

    def _deserialize(self, value, *args, **kwargs) -> x509.NameAttribute:
        return x509.NameAttribute(NameOID.COUNTRY_NAME, value)


CountryNameOID = NewType("CountryNameOID", str, field=CountryNameOIDType)


class StateOrProvinceOIDType(marshmallow.fields.Field):
    """x509 State or Province Name"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.value

    def _deserialize(self, value, *args, **kwargs) -> x509.NameAttribute:
        return x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value)


StateOrProvinceOID = NewType("StateOrProvinceOID", str, field=StateOrProvinceOIDType)


class LocalityOIDType(marshmallow.fields.Field):
    """x509 Locality Name"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.value

    def _deserialize(self, value, *args, **kwargs) -> x509.NameAttribute:
        return x509.NameAttribute(NameOID.LOCALITY_NAME, value)


LocalityOID = NewType("LocalityOID", str, field=LocalityOIDType)


class OrganizationOIDType(marshmallow.fields.Field):
    """x509 Organization Name"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.value

    def _deserialize(self, value, *args, **kwargs) -> x509.NameAttribute:
        return x509.NameAttribute(NameOID.ORGANIZATION_NAME, value)


OrganizationOID = NewType("OrganizationOID", str, field=OrganizationOIDType)


class OrganizationalUnitOIDType(marshmallow.fields.Field):
    """x509 Organizational Unit Name"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.value

    def _deserialize(self, value, *args, **kwargs) -> x509.NameAttribute:
        return x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value)


OrganizationalUnitOID = NewType(
    "OrganizationalUnitOID", str, field=OrganizationalUnitOIDType
)


### ACME Types


class RegistrationType(marshmallow.fields.Field):
    """ACME Account Registration"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.to_json()

    def _deserialize(self, value, *args, **kwargs) -> messages.RegistrationResource:
        return messages.RegistrationResource.from_json(value)


Registration = NewType("Registration", dict, field=RegistrationType)


class OrderType(marshmallow.fields.Field):
    """ACME Account Registration"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return value.to_json()

    def _deserialize(self, value, *args, **kwargs) -> messages.OrderResource:
        if value is None:
            return None
        body = messages.Order.from_json(value["body"])
        uri = value["uri"]
        csr_pem = bytes(value["csr_pem"])
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


Order = NewType("Order", dict, field=OrderType)


### Generic types


class PathType(marshmallow.fields.Field):
    """File Path"""

    def _serialize(self, value, *args, **kwargs) -> str | None:
        if value is None:
            return None
        return str(value)

    def _deserialize(self, value, *args, **kwargs) -> pathlib.Path:
        return pathlib.Path(value)


Path = NewType("Path", str, field=PathType)


Domain = NewType(
    "Domain",
    str,
    validate=marshmallow.validate.Regexp(
        # taken from https://github.com/python-validators/validators/blob/0.20.0/validators/domain.py#L5-L10
        r"^(?:[a-zA-Z0-9]"  # First character of the domain
        r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
        r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
        r"[A-Za-z]$"
    ),
)
Email = NewType("Email", str, field=marshmallow.fields.Email)
Url = NewType("Url", str, field=marshmallow.fields.Url)
TimeDelta = NewType("TimeDelta", int, field=marshmallow.fields.TimeDelta)
PolyField = NewType("PolyField", dict, field=marshmallow_polyfield.PolyField)
