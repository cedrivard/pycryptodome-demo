#!/bin/env python
""" This script generates checksum for a file, creates signature with a private
key file, and verifies the signature using the public key extracted from a
certificate file.
"""
import base64
import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generate_signature(pv_key_file: str, chksum: str) -> bytes:
    """Generate signature for a given chksum using a private key file.

    Args:
        private_key_file (str): Path to the private key file in PEM format.
        chksum (str): The chksum that will be used to generate the signature.

    Returns:
        bytes: Signature for the given chksum in bytes format encoded with base64.
    """
    privkey: RSA.RsaKey = RSA.import_key(open(pv_key_file, encoding="utf-8").read())
    return base64.b64encode(pkcs1_15.new(privkey).sign(chksum))


def verify_signature(cert_file: str, chksum: str, signatr: bytes) -> bool:
    """Verify a signatr for a given chksum using a certificate file.

    Args:
        cert_file (str): Path to the certificate file in PEM format.
        chksum (str): The chksum that will be used to verify the signatr.
        signatr (bytes): Signature that needs to be verified, encoded with base64.

    Returns:
        bool: True if the signatr is valid for the given chksum and
        certificate file. False otherwise.
    """
    pubkey: RSA.RsaKey = RSA.import_key(open(cert_file, encoding="utf-8").read())
    try:
        pkcs1_15.new(pubkey).verify(chksum, signatr)
        return True
    except:
        return False


def generate_checksum(file: str) -> SHA256.SHA256Hash:
    """Generate a checksum for the content of given file.

    Args:
        file (str): Path to the file that will be used to calculate the checksum.

    Returns:
        SHA256.SHA256Hash: Checksum of the content of the file.
    """
    return SHA256.new(open(file, encoding="utf-8").read().encode())


if __name__ == "__main__":
    param: str = sys.argv[1]

    if param == "-s":
        private_key_file: str = sys.argv[2]
        data_file: str = sys.argv[3]
        signature_checksum_file: str = sys.argv[4]
        checksum: str = generate_checksum(data_file)
        signature: bytes = generate_signature(private_key_file, checksum)

        with open(signature_checksum_file, "w", encoding="utf-8") as f:
            f.write("Checksum: " + checksum.hexdigest() + "\n")
            f.write("Signature: " + signature.decode("utf-8") + "\n")
    elif param == "-v":
        certificate_file: str = sys.argv[2]
        data_file: str = sys.argv[3]
        signature_checksum_file: str = sys.argv[4]

        checksum: str = generate_checksum(data_file)
        with open(signature_checksum_file, "r", encoding="utf-8") as f:
            lines: list[str] = f.readlines()
        signature: bytes = base64.b64decode(lines[1][11:].strip())

        if verify_signature(certificate_file, checksum, signature):
            print("Signature verification succeeded")
        else:
            print("Signature verification failed")
    else:
        print("Invalid parameter. Use either -s or -v")
