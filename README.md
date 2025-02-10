# OpenSSH key to JWKS 🌿
A simple tool to generate a (https://datatracker.ietf.org/doc/html/rfc7517)[JSON Web Key Set (JWKS)] from a keyfile generated e.g. with `ssh-keygen`.

## Usage
Generate a key e.g. with `ssh-keygen`:
```bash
ssh-keygen -t ed25519 -f key
```

Generate a JWKS from the private key file using Docker:
```bash
docker build -t jwks .
MSYS_NO_PATHCONV=1 docker run --volume "$PWD:/app" -it jwks key
```

## Without Docker
Install dependencies with
```bash
pip install -r requirements.txt
```

Run with
```bash
py ssh_to_jwks.py key
```
