"""
This module contains state schema migrations that should be applied.
"""

from typing import Any, Callable, Dict, List

import josepy.jwk
from cryptography.hazmat.primitives import serialization


def _account_migration_00_switch_jwk_to_pem(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Switch from storing a JWK private key to a PEM-encoded key.
    """
    key = data.pop("key", None)
    if not isinstance(key, dict):
        data["key"] = key
        return data
    jwk = josepy.jwk.JWKRSA.from_json(key)
    # Access the internal cryptography key. josepy doesn't provide a public API for this.
    wrapped_key = jwk.key._wrapped  # type: ignore[attr-defined]
    data["key"] = wrapped_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return data


def _cert_migration_00_add_chain(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Switch from storing the CA and intermediate(s) separately to a generic
    chain field.

    This is done to more accurately represent what is returned from the
    ACME server based on RFC 8555. The trust anchor (CA cert) is not
    required to be returned, but can be optionally.
    """
    chain = []
    intermediates = data.pop("intermediates", None)
    ca = data.pop("ca", None)
    if isinstance(intermediates, list):
        for intermediate in intermediates:
            if intermediate is not None:
                chain.append(intermediate)
    if ca is not None:
        chain.append(ca)
    data["chain"] = chain if chain else None
    return data


# State schema migrations.
# Order matters! Migrations are applied in the order they are defined in this list.
# The _schema_version saved to the state is based on the length of these lists.
ACCOUNT_STATE_SCHEMA_MIGRATIONS: List[Callable[[Dict[str, Any]], Dict[str, Any]]] = [
    _account_migration_00_switch_jwk_to_pem,
]
CERT_STATE_SCHEMA_MIGRATIONS: List[Callable[[Dict[str, Any]], Dict[str, Any]]] = [
    _cert_migration_00_add_chain,
]
