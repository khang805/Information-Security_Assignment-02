#!/usr/bin/env python3
import os, sys, datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = "certs"
CA_KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")

def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def issue_cert(common_name: str, filename_prefix: str):
    os.makedirs(OUT_DIR, exist_ok=True)
    ca_key, ca_cert = load_ca()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sargodha"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=True, key_agreement=True,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
        ), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    key_path = os.path.join(OUT_DIR, f"{filename_prefix}.key.pem")
    cert_path = os.path.join(OUT_DIR, f"{filename_prefix}.cert.pem")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{filename_prefix} key: {key_path}")
    print(f"{filename_prefix} cert: {cert_path}")

def main():
    if len(sys.argv) != 3:
        print("Usage: scripts/gen_cert.py <common_name> <filename_prefix>")
        print("Example: scripts/gen_cert.py server.local server")
        sys.exit(1)
    cn, prefix = sys.argv[1], sys.argv[2]
    issue_cert(cn, prefix)

if __name__ == "__main__":
    main()
