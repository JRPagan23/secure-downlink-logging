import os
import base64
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac

# Load AES key
def load_key(path):
    with open(path, "rb") as f:
        key = f.read()
    key_bytes = base64.urlsafe_b64decode(key)
    if len(key_bytes) not in [16, 24, 32]:
        raise ValueError("AES key must be 128, 192, or 256 bits.")
    return key_bytes

# Encrypt message
def encrypt(plaintext, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext[-16:]
    ciphertext_body = ciphertext[:-16]
    return ciphertext_body, nonce, tag

# Decrypt message
def decrypt(ciphertext, nonce, tag, key):
    aesgcm = AESGCM(key)
    try:
        full_cipher = ciphertext + tag
        return aesgcm.decrypt(nonce, full_cipher, None)
    except Exception as e:
        raise ValueError("Decryption failed.") from e

# HMAC for authenticity
def generate_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

# HMAC verification
def verify_hmac(signature, data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(signature)
        return True
    except Exception:
        return False
