import secrets
from cryptography.hazmat.primitives import hashes

# Classic DH with known safe prime and generator (RFC 3526 small subset).
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
DH_G = 2

def dh_generate_private(bits: int = 256) -> int:
    return secrets.randbits(bits)

def dh_public(g: int, p: int, a: int) -> int:
    return pow(g, a, p)

def dh_shared(peer_pub: int, p: int, a: int) -> int:
    return pow(peer_pub, a, p)

def sha256_bytes(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()

def k_from_shared(Ks: int) -> bytes:
    be = Ks.to_bytes((Ks.bit_length() + 7) // 8, "big")
    return sha256_bytes(be)[:16]  # Trunc16(SHA256(big-endian(Ks)))
