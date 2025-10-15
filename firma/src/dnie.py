import base64
import platform
import pkcs11
from pkcs11 import Mechanism, ObjectClass
import os
import hashlib

class DNIeManager:
    def __init__(self):
        # Configurar ruta de librería según el sistema operativo
        system = platform.system()
        if system == "Windows":
            self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"    #"C:\Windows\System32\aetpkss1.dll"  # Driver DNIe Windows
        elif system == "Darwin":  # macOS
            self.lib_path = "/usr/lib/opensc-pkcs11.so"
        else:  # Linux
            self.lib_path = "/usr/lib/opensc-pkcs11.so"
        
        self.session = None
    
    def authenticate(self, pin: str) -> bytes:
        """Authenticate with DNIe and return derived key"""
        try:
            lib = pkcs11.lib(self.lib_path)
            slots = lib.get_slots(token_present=True)
            
            if not slots:
                raise Exception(f"No DNIe found. Please insert your DNIe card. (Using: {self.lib_path})")
            
            token = slots[0].get_token()
            self.session = token.open(user_pin=pin)
            
            # Get private key for signing
            priv_key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                label='Certificado Digital de Autenticación'
            )
            
            # Create and sign challenge
            challenge = os.urandom(32)
            signature = priv_key.sign(challenge, mechanism=Mechanism.SHA256_RSA_PKCS)
            
            # Derive key from signature
            return self._derive_key(signature)
            
        except pkcs11.PKCS11Error as e:
            if "CKR_PIN_INCORRECT" in str(e):
                raise Exception("Incorrect PIN. Please check your DNIe PIN.")
            elif "CKR_PIN_LOCKED" in str(e):
                raise Exception("DNIe locked. Too many incorrect PIN attempts.")
            else:
                raise Exception(f"PKCS#11 error: {str(e)}")
        except FileNotFoundError:
            raise Exception(f"PKCS#11 library not found at: {self.lib_path}\n"
                          f"Please install DNIe drivers for {platform.system()}")
        except Exception as e:
            raise Exception(f"DNIe authentication failed: {str(e)}")
    
    def _derive_key(self, signature: bytes) -> bytes:
        """Derive Fernet key from signature"""
        # Use HMAC to derive consistent key from signature
        derived = hashlib.pbkdf2_hmac('sha256', signature, b'dnie_salt', 100000, 32)
        return base64.urlsafe_b64encode(derived)
    
    def close(self):
        """Close DNIe session"""
        if self.session:
            self.session.close()