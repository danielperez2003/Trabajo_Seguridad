import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class CryptoManager:
    def __init__(self):
        self.fernet = None
        self.db_file = "passwords.db.enc"
    
    def initialize_db(self, key: bytes):
        """Initialize encrypted database with master key"""
        self.fernet = Fernet(key)
        empty_db = {"entries": []}
        self._save_db(empty_db)
    
    def _save_db(self, db_dict: dict):
        """Encrypt and save database"""
        plaintext = json.dumps(db_dict).encode()
        ciphertext = self.fernet.encrypt(plaintext)
        with open(self.db_file, 'wb') as f:
            f.write(ciphertext)
    
    def load_db(self) -> dict:
        """Decrypt and load database"""
        try:
            with open(self.db_file, 'rb') as f:
                ciphertext = f.read()
            plaintext = self.fernet.decrypt(ciphertext)
            return json.loads(plaintext.decode())
        except FileNotFoundError:
            return {"entries": []}
    
    def add_password(self, service: str, username: str, password: str):
        """Add password entry"""
        db = self.load_db()
        db["entries"].append({
            "service": service,
            "username": username,
            "password": password
        })
        self._save_db(db)
    
    def list_entries(self):
        """List all password entries"""
        db = self.load_db()
        return db["entries"]