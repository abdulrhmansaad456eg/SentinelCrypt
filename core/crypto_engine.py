import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

class CryptoEngine:
    """
    Core engine handling AES-256-GCM and RSA operations.
    """

    def __init__(self):
        self.backend = default_backend()

    def generate_aes_key(self):
        """Generates a secure 32-byte (256-bit) AES key."""
        return os.urandom(32)

    def aes_encrypt(self, data: bytes, key: bytes) -> dict:
        """
        Encrypts data using AES-256-GCM.
        Returns: { 'ciphertext': bytes, 'iv': bytes, 'tag': bytes }
        """
        
        iv = os.urandom(12)

        
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        ).encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'tag': encryptor.tag
        }

    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """
        Decrypts data using AES-256-GCM.
        Verifies integrity using the tag.
        """
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        ).decryptor()

        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            raise ValueError("Decryption failed. Integrity check failed or wrong key.")

    def rsa_encrypt_key(self, aes_key: bytes, public_key) -> bytes:
        """Encrypts an AES key using an RSA Public Key."""
        return public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt_key(self, encrypted_aes_key: bytes, private_key) -> bytes:
        """Decrypts an AES key using an RSA Private Key."""
        return private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )