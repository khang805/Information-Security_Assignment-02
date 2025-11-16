from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509

# RSA PKCS#1 v1.5 + SHA-256 (as skeleton specifies)

def rsa_sign_pkcs1v15(priv_pem_path: str, data: bytes) -> bytes:
    with open(priv_pem_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())

def rsa_verify_pkcs1v15(cert_pem_path: str, data: bytes, sig: bytes) -> bool:
    with open(cert_pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    pub = cert.public_key()
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
