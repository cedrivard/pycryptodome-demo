#!/bin/env python
""" This script generates a private key, a certificate signing request
and a self signed certificate in PEM format.
"""
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a new RSA private key with a key size of 2048 bits and public exponent of 65537."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_csr(pv_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    """Generate a certificate signing request (CSR) using the provided private
    key and set of subject details.
    """
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )

    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(pv_key, hashes.SHA256())
    )


def generate_self_signed_certificate(
    csreq: x509.CertificateSigningRequest, pv_key: rsa.RSAPrivateKey
) -> x509.Certificate:
    """Generate a self-signed certificate using the provided CSR and private key."""
    return (
        x509.CertificateBuilder()
        .issuer_name(csreq.subject)
        .subject_name(csreq.subject)
        .public_key(csreq.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=10 * 365),
        )
        .sign(pv_key, hashes.SHA256())
    )


# Generate private key
private_key: rsa.RSAPrivateKey = generate_private_key()

# Write the private key to a file
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Generate CSR
csr: x509.CertificateSigningRequest = generate_csr(private_key)
# Write the CSR to a file
with open("certificate_signing_request.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# Generate self signed certificate
self_signed_certificate: x509.Certificate = generate_self_signed_certificate(
    csr, private_key
)

# Write the Certificate to a file
with open("self_signed_certificate.pem", "wb") as f:
    f.write(self_signed_certificate.public_bytes(serialization.Encoding.PEM))
