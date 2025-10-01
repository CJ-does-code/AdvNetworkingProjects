from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import uuid

def get_mac_address():
    mac = uuid.getnode()
    mac_str = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
    return mac_str

def derive_symmetric_key(network_token: bytes, length=32, iterations=100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"factory salt set by manufacturer or codebase-secretkeeper",
        iterations=iterations,
        backend=default_backend()
    )
    combined_input = network_token + "factory salt set by manufacturer or codebase-secretkeeper"
    return kdf.derive(combined_input.encode())


# Encrypt message and return a single binary payload: [IV | CIPHERTEXT | MAC]
def encrypt_message(message: bytes, key: bytes) -> bytes:
    # Pad
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(message) + padder.finalize()

    # Encrypt with AES-CBC
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()

    # MAC (HMAC over ciphertext)
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    mac_tag = h.finalize()

    # Return: IV + ciphertext + MAC tag
    return iv + ciphertext + mac_tag

# Decrypt message and verify MAC
def decrypt_message(blob: bytes, key: bytes) -> bytes:
    iv = blob[:16]
    mac_tag = blob[-32:]
    ciphertext = blob[16:-32]

    # Verify MAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(mac_tag)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext