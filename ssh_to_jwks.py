import json
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.backends import default_backend
from crypto import jwks

def read_ssh_private_key(filename: str):
    """Reads an OpenSSH private key and determines its type."""
    with open(filename, "rb") as f:
        key_data = f.read()

    # Load the private key with or without password
    try:
        private_key = load_ssh_private_key(key_data, password=None, backend=default_backend())
    except Exception as e:
        if str(e) != "Key is password-protected.":
            raise e
        password = getpass("Password: ").encode()
        private_key = load_ssh_private_key(key_data, password=password, backend=default_backend())

    # Convert to JWK
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return jwks.from_ed25519(private_key)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        return jwks.from_rsa(private_key)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return jwks.from_ecdsa(private_key)
    else:
        raise ValueError("Unsupported key type")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python ssh_to_jwks.py <ssh_private_key_file>")
        sys.exit(1)

    key_file = sys.argv[1]
    # try:
    private_jwk, public_jwk = read_ssh_private_key(key_file)

    jwks = {"keys": [public_jwk, private_jwk]}  # JWKS format

    with open("jwks.json", "w") as f:
        json.dump(jwks, f, indent=2)

    print("✅ JWKS saved to jwks.json")
