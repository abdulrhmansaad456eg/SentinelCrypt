"""
Unit tests for the file encryption and key management components.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.file_crypto import FileCrypto
from core.key_manager import KeyManager


class TestFileCrypto(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.crypto = FileCrypto()

    def test_roundtrip(self):
        src = os.path.join(self.tmp, "plain.txt")
        message = b"roundtrip test data " * 50
        with open(src, "wb") as f:
            f.write(message)

        enc_path = self.crypto.encrypt_file(src, "correct-password")
        self.assertTrue(os.path.exists(enc_path))

        dec_path = self.crypto.decrypt_file(enc_path, "correct-password")
        with open(dec_path, "rb") as f:
            self.assertEqual(f.read(), message)

    def test_wrong_password_rejected(self):
        src = os.path.join(self.tmp, "plain.txt")
        with open(src, "wb") as f:
            f.write(b"secret data")

        enc_path = self.crypto.encrypt_file(src, "correct-password")
        with self.assertRaises(Exception):
            self.crypto.decrypt_file(enc_path, "wrong-password")


class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.manager = KeyManager(key_dir=os.path.join(self.tmp, "keys"))

    def test_key_pair_generation(self):
        self.manager.generate_key_pair("alice", "key-password")
        files = os.listdir(self.manager.key_dir)
        self.assertTrue(len(files) >= 2, f"expected key files, got {files}")


if __name__ == "__main__":
    unittest.main()
