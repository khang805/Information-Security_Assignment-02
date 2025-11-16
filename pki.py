import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def validate_cert(cert_pem: bytes, ca_cert_pem: bytes, expected_cn: str) -> (bool, str):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca = x509.load_pem_x509_certificate(ca_cert_pem)

        if cert.issuer != ca.subject:
            return False, "BAD_CERT_ISSUER"

        try:
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        except Exception:
            return False, "BAD_CERT_SIGNATURE"

        now = time.time()
        if not (cert.not_valid_before.timestamp() <= now <= cert.not_valid_after.timestamp()):
            return False, "BAD_CERT_EXPIRED"

        cn = None
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attr.value
                break
        if cn != expected_cn:
            return False, "BAD_CERT_CN"
        return True, "OK"
    except Exception:
        return False, "BAD_CERT_PARSE"

def cert_fingerprint_sha256(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex()
