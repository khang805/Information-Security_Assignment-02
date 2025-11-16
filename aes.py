from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import secrets

# AES-128(ECB) + PKCS#7, as skeleton specifies "block only"
# Note: ECB lacks IV; per assignment, integrity/authenticity are provided via RSA signatures.

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt_ecb(k16: bytes, plaintext: bytes) -> bytes:
    pt = pkcs7_pad(plaintext, 16)
    cipher = Cipher(algorithms.AES(k16), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(pt) + enc.finalize()

def aes_decrypt_ecb(k16: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(k16), modes.ECB())
    dec = cipher.decryptor()
    pt_padded = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(pt_padded, 16)
