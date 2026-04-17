import josepy.jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from certwrangler.schema_migrations import (
    _account_and_cert_migration_01_add_key_algorithm,
    _account_migration_00_switch_jwk_to_pem,
    _cert_migration_00_add_chain,
)


class TestAccountStateSchemaMigrations:
    """
    Tests for account state schema migrations.
    """

    def test__account_migration_00_switch_jwk_to_pem(self):
        """
        Test that we migrate from JWK to PEM correctly.
        """
        # Test with a JWK dictionary
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = josepy.jwk.JWKRSA(key=private_key)
        data = {"key": jwk.to_json()}

        migrated_data = _account_migration_00_switch_jwk_to_pem(data)

        # Verify it's now a PEM string
        assert isinstance(migrated_data["key"], str)
        assert migrated_data["key"].startswith("-----BEGIN PRIVATE KEY-----")

        # Verify the PEM is valid and matches the original key
        loaded_key = serialization.load_pem_private_key(
            migrated_data["key"].encode(), password=None
        )
        assert loaded_key.public_key() == private_key.public_key()

        # Test with a value that is already a PEM string (should be left alone)
        pem_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n dummy \n-----END RSA PRIVATE KEY-----"
        )
        data = {"key": pem_key}
        assert _account_migration_00_switch_jwk_to_pem(data) == {"key": pem_key}

        # Test with None (should be left alone)
        data = {"key": None}
        assert _account_migration_00_switch_jwk_to_pem(data) == {"key": None}


class TestCertStateSchemaMigrations:
    """
    Tests for cert state schema migrations.
    """

    def test__cert_migration_00_add_chain(self):
        """
        Test that we migrate to the chain field correctly.
        """
        # Test with none values for ca and intermediates, should result in chain being None.
        data = {"ca": None, "intermediates": None}
        assert _cert_migration_00_add_chain(data) == {"chain": None}
        # Add a ca, we should see that move to a list under the "chain" key.
        data = {"ca": "test ca", "intermediates": None}
        assert _cert_migration_00_add_chain(data) == {"chain": ["test ca"]}
        # Same with intermediates.
        data = {
            "ca": None,
            "intermediates": ["test intermediate 1", "test intermediate 2"],
        }
        assert _cert_migration_00_add_chain(data) == {
            "chain": ["test intermediate 1", "test intermediate 2"]
        }
        # Now test with both populated, we should see the ca tacked to the end of the chain.
        data = {
            "ca": "test ca",
            "intermediates": ["test intermediate 1", "test intermediate 2"],
        }
        assert _cert_migration_00_add_chain(data) == {
            "chain": ["test intermediate 1", "test intermediate 2", "test ca"]
        }


class TestCommonSchemaMigrations:
    """
    Tests for common state schema migrations.
    """

    def test__account_and_cert_migration_01_add_key_algorithm(self):
        """
        Test that we add key_algorithm correctly.
        """
        # Test without key_algorithm
        data = {"some_other_field": "value"}
        migrated_data = _account_and_cert_migration_01_add_key_algorithm(data)
        assert migrated_data["key_algorithm"] == "RSA"

        # Test with key_algorithm already present
        data = {"key_algorithm": "EC"}
        assert _account_and_cert_migration_01_add_key_algorithm(data) == {
            "key_algorithm": "EC"
        }
