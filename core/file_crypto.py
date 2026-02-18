import os
from core.crypto_engine import CryptoEngine

class FileCrypto:
    def __init__(self):
        self.engine = CryptoEngine()

    def encrypt_file(self, file_path, password_str):
        """
        Encrypts a file using a derived key from a password (simplified for single-user use).
        For this simplified version, we use a hashed password as the AES key.
        In a hybrid system, we would generate a random AES key and encrypt it with RSA.
        Here, we implement Symmetric File Encryption using Password.
        """
        
        
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.engine.backend
        )
        key = kdf.derive(password_str.encode())

        
        with open(file_path, 'rb') as f:
            data = f.read()

        
        result = self.engine.aes_encrypt(data, key)

        
        out_path = file_path + ".enc"
        with open(out_path, 'wb') as f:
            f.write(salt)
            f.write(result['iv'])
            f.write(result['tag'])
            f.write(result['ciphertext'])
        
        return out_path

    def decrypt_file(self, file_path, password_str):
        """Decrypts a file encoded with the encrypt_file method."""
        with open(file_path, 'rb') as f:
            file_data = f.read()

        
        salt = file_data[:16]
        iv = file_data[16:28]
        tag = file_data[28:44]
        ciphertext = file_data[44:]

    
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.engine.backend
        )
        key = kdf.derive(password_str.encode())

        
        decrypted_data = self.engine.aes_decrypt(ciphertext, key, iv, tag)

        
        out_path = file_path.replace(".enc", ".decrypted")
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
            
        return out_path