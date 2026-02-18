import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class KeyManager:
    """
    Manages generation, storage, and loading of RSA keys.
    """

    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)

    def generate_key_pair(self, name, password: str):
        """
        Generates RSA-2048 private/public key pair.
        Private key is encrypted with the provided password.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        
        priv_path = os.path.join(self.key_dir, f"{name}_private.pem")
        pub_path = os.path.join(self.key_dir, f"{name}_public.pem")

        with open(priv_path, "wb") as f:
            f.write(pem_private)
        
        with open(pub_path, "wb") as f:
            f.write(pem_public)

        return priv_path, pub_path

    def load_private_key(self, name, password: str):
        """Loads a password-protected private key."""
        path = os.path.join(self.key_dir, f"{name}_private.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key for {name} not found.")

        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
        return private_key

    def load_public_key(self, name):
        """Loads a public key."""
        path = os.path.join(self.key_dir, f"{name}_public.pem")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key for {name} not found.")

        with open(path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key