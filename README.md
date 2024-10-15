# PyCryptodome Demo Project: Signing and Verifying Files

This is a simple demonstration of signing files using a private key, and verifying the signature later on with a public key extracted from a certificate file using pycryptodome module in python. The scripts involved are `certificates.py` for generating certificates, private keys, and CSRs, and `signing.py` to generate checksums and sign files as well as verify signatures.

## certificates.py:
This script generates a private key (RSA) with a modulus of 2048 bits and a public exponent of 65537. It also creates a certificate signing request (CSR), and finally signs the CSR to generate self-signed certificate using the same private key. All keys and certificates are stored in PEM format files (`private_key.pem`, `certificate_signing_request.pem`, and `self_signed_certificate.pem`).

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
# ... (remainder of the script)
```
The `generate_private_key` function generates an RSA private key, and the `generate_csr` function uses this key to generate a CSR with specified subject details. The `generate_self_signed_certificate` function then creates a self-signed certificate based on the CSR and private key.

## signing.py:
This script generates checksums using SHA256 algorithm for files, sign files with private keys using PKCS1v15 signature scheme, and verify signatures with public certificates.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
# ... (remainder of the script)
```
The `generate_signature` function uses a private key to generate PKCS1v15 signatures for checksums, while the `verify_signature` function verifies these signatures using public keys extracted from certificates. The `generate_checksum` function is used to create SHA256 checksums of file contents.

To use this:
1. Save both scripts in the same directory as each other, and optionally a test file you'd like to sign/verify.
2. Run `python certificates.py` to generate keys and certificate files.
3. Run `python signing.py -s private_key.pem yourfile.ext signature_checksum.txt` to sign the specified file with the private key, generating a checksum and signature.
4. Run `python signing.py -v self_signed_certificate.pem yourfile.ext signature_checksum.txt` to verify the signature of the specified file using the generated certificate.
5. If successful, it should print "Signature verification succeeded" or indicate "Signature verification failed" as appropriate.
