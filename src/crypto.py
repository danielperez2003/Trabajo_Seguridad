# crypto.py - Cifrado y gestión de contraseñas con DNIe
import json
import os
from cryptography.fernet import Fernet
from dnie import DNIeManager
import getpass

class CryptoManager:
    def __init__(self):
        self.fernet = None
        self.db_file = "passwords.db.enc"
        self.dnie_manager = None
    
    def authenticate_with_dnie(self):
        """Autenticar con DNIe y configurar clave de cifrado"""
        try:
            pin = getpass.getpass("🔒 Introduzca el PIN de su DNIe: ")
            self.dnie_manager = DNIeManager()
            key = self.dnie_manager.authenticate(pin)
            self.fernet = Fernet(key)
            return True
        except Exception as e:
            print(f"❌ Error de autenticación DNIe: {e}")
            return False
    
    def initialize_db(self):
        """Initialize encrypted database with DNIe key"""
        if not self.authenticate_with_dnie():
            raise Exception("No se pudo autenticar con DNIe")
        
        empty_db = {"entries": []}
        self._save_db(empty_db)
    
    def _save_db(self, db_dict: dict):
        """Encrypt and save database"""
        if not self.fernet:
            raise Exception("No autenticado con DNIe")
            
        plaintext = json.dumps(db_dict).encode()
        ciphertext = self.fernet.encrypt(plaintext)
        with open(self.db_file, 'wb') as f:
            f.write(ciphertext)
    
    def load_db(self) -> dict:
        """Decrypt and load database"""
        if not self.fernet:
            if not self.authenticate_with_dnie():
                raise Exception("No se pudo autenticar con DNIe")
                
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
    
    def update_password(self, service: str, username: str, password: str):
        """Update existing password entry"""
        db = self.load_db()
        for entry in db["entries"]:
            if entry["service"] == service and entry["username"] == username:
                entry["password"] = password
                self._save_db(db)
                return True
        return False
    
    def delete_password(self, service: str, username: str):
        """Delete password entry"""
        db = self.load_db()
        db["entries"] = [entry for entry in db["entries"] 
                        if not (entry["service"] == service and entry["username"] == username)]
        self._save_db(db)
    
    def close(self):
        """Cerrar sesión DNIe"""
        if self.dnie_manager:
            self.dnie_manager.close()