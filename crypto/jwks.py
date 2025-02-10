from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from crypto import utils

def from_ed25519(private_key: ed25519.Ed25519PrivateKey):
    """Exports an Ed25519 key as both private and public JWK."""
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    jwk_public = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": utils.base64url_encode(public_bytes),
        "use": "sig",
    }

    jwk_private = {
        **jwk_public,
        "d": utils.base64url_encode(private_bytes),
    }

    return jwk_private, jwk_public


def from_rsa(private_key: rsa.RSAPrivateKey):
    """Exports an RSA key as both private and public JWK."""
    numbers = private_key.private_numbers()

    jwk_public = {
        "kty": "RSA",
        "n": utils.base64url_encode(utils.big_endian_encode(numbers.public_numbers.n)),
        "e": utils.base64url_encode(utils.big_endian_encode(numbers.public_numbers.e)),
        "use": "sig",
    }

    jwk_private = {
        **jwk_public,
        "d": utils.base64url_encode(utils.big_endian_encode(numbers.d)),
        "p": utils.base64url_encode(utils.big_endian_encode(numbers.p)),
        "q": utils.base64url_encode(utils.big_endian_encode(numbers.q)),
        "dp": utils.base64url_encode(utils.big_endian_encode(numbers.dmp1)),
        "dq": utils.base64url_encode(utils.big_endian_encode(numbers.dmq1)),
        "qi": utils.base64url_encode(utils.big_endian_encode(numbers.iqmp)),
    }

    return jwk_private, jwk_public


def from_ecdsa(private_key: ec.EllipticCurvePrivateKey):
    """Exports an ECDSA key as both private and public JWK."""
    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers

    jwk_public = {
        "kty": "EC",
        "crv": private_key.curve.name,
        "x": utils.base64url_encode(public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, "big")),
        "y": utils.base64url_encode(public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, "big")),
        "use": "sig",
    }

    jwk_private = {
        **jwk_public,
        "d": utils.base64url_encode(numbers.private_value.to_bytes((numbers.private_value.bit_length() + 7) // 8, "big")),
    }

    return jwk_private, jwk_public