import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from certwrangler.types import _algorithm_loader, _curve_loader, _private_key_loader


class TestAlgorithmLoader:
    """
    Tests for the _algorithm_loader function.
    """

    def test_load_ec_string(self):
        """
        Test that EC algorithm string loads correctly.
        """
        assert _algorithm_loader("EC") == ec.EllipticCurvePrivateKey

    def test_load_rsa_string(self):
        """
        Test that RSA algorithm string loads correctly.
        """
        assert _algorithm_loader("RSA") == rsa.RSAPrivateKey

    def test_load_ec_type(self):
        """
        Test that EC algorithm type passes through correctly.
        """
        assert (
            _algorithm_loader(ec.EllipticCurvePrivateKey) == ec.EllipticCurvePrivateKey
        )

    def test_load_rsa_type(self):
        """
        Test that RSA algorithm type passes through correctly.
        """
        assert _algorithm_loader(rsa.RSAPrivateKey) == rsa.RSAPrivateKey

    def test_invalid_string_raises(self):
        """
        Test that an unsupported algorithm string raises ValueError.
        """
        with pytest.raises(ValueError, match="Unsupported algorithm: ED25519"):
            _algorithm_loader("ED25519")


class TestCurveLoader:
    """
    Tests for the _curve_loader function.
    """

    def test_load_p256_string(self):
        """
        Test that P-256 curve string loads correctly.
        """
        assert _curve_loader("P-256") == ec.SECP256R1

    def test_load_p384_string(self):
        """
        Test that P-384 curve string loads correctly.
        """
        assert _curve_loader("P-384") == ec.SECP384R1

    def test_load_p521_string(self):
        """
        Test that P-521 curve string loads correctly.
        """
        assert _curve_loader("P-521") == ec.SECP521R1

    def test_load_curve_type(self):
        """
        Test that curve type passes through correctly.
        """
        assert _curve_loader(ec.SECP256R1) == ec.SECP256R1

    def test_invalid_string_raises(self):
        """
        Test that an unsupported curve string raises ValueError.
        """
        with pytest.raises(ValueError, match="Unsupported curve: brainpoolP256r1"):
            _curve_loader("brainpoolP256r1")


class TestPrivateKeyLoader:
    """
    Tests for the _private_key_loader function.
    """

    def test_load_rsa_pem(self):
        """
        Test that RSA PEM string loads correctly.
        """
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        result = _private_key_loader(pem)
        assert isinstance(result, rsa.RSAPrivateKey)

    def test_load_ec_pem(self):
        """
        Test that EC PEM string loads correctly.
        """
        ec_key = ec.generate_private_key(ec.SECP256R1())
        pem = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        result = _private_key_loader(pem)
        assert isinstance(result, ec.EllipticCurvePrivateKey)

    def test_pass_ec_instance(self):
        """
        Test that EC key instance passes through correctly.
        """
        ec_key = ec.generate_private_key(ec.SECP256R1())
        result = _private_key_loader(ec_key)
        assert result is ec_key

    def test_pass_rsa_instance(self):
        """
        Test that RSA key instance passes through correctly.
        """
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        result = _private_key_loader(rsa_key)
        assert result is rsa_key

    def test_unsupported_type_raises(self):
        """
        Test that an unsupported key type loaded from PEM raises ValueError.
        """
        ed25519_key = Ed25519PrivateKey.generate()
        pem = ed25519_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        with pytest.raises(
            ValueError,
            match="Unsupported private key type: <class '.*Ed25519PrivateKey'>",
        ):
            _private_key_loader(pem)
