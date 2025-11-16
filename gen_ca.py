#!/usr/bin/env python3
import os, datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = "certs"
CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sargodha"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat-Root-CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA key: {CA_KEY_PATH}")
    print(f"CA cert: {CA_CERT_PATH}")

if __name__ == "__main__":
    main()
