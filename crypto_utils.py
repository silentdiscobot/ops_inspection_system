# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def aes_gcm_encrypt(key: bytes, plaintext: str) -> str:
    """
    Encrypt plaintext (utf-8) with AES-GCM.
    Returns base64 string of nonce + ciphertext + tag.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)  # returns ciphertext+tag
    blob = nonce + ct
    return base64.b64encode(blob).decode("utf-8")

def aes_gcm_decrypt(key: bytes, blob_b64: str) -> str:
    """
    Decrypt base64(nonce + ciphertext + tag) and return utf-8 string.
    """
    data = base64.b64decode(blob_b64)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")
