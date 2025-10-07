import pkcs11
from pkcs11 import Mechanism, ObjectClass, Attribute
import hashlib
import os
from typing import Optional, Tuple

class DNIeClient:
    def __init__(self, lib_path: str = "/usr/lib/opensc-pkcs11.so"):
        """
        Initialize DNIe client with PKCS#11 library path.
        
        Args:
            lib_path: Path to PKCS#11 library (opensc-pkcs11.so on Linux)
        """
        self.lib_path = lib_path
        self.session = None
        self._lib = None
    
    def connect(self, pin: str) -> bool:
        """
        Establish connection to DNIe smart card and authenticate with PIN.
        
        Args:
            pin: DNIe PIN as string
            
        Returns:
            bool: True if connection successful
            
        Raises:
            Exception: If no DNIe found or authentication fails
        """
        try:
            # Load PKCS#11 library
            self._lib = pkcs11.lib(self.lib_path)
            
            # Get available slots with tokens present
            slots = self._lib.get_slots(token_present=True)
            
            if not slots:
                raise Exception("No DNIe card found. Please insert your DNIe.")
            
            # Get first available token and open session
            token = slots[0].get_token()
            self.session = token.open(user_pin=pin, rw=True)
            return True
            
        except Exception as e:
            raise Exception(f"DNIe connection failed: {str(e)}")
    
    def get_certificate(self) -> Optional[bytes]:
        """
        Extract X.509 certificate from DNIe.
        
        Returns:
            Optional[bytes]: DER-encoded certificate bytes or None if not found
            
        Raises:
            Exception: If not connected to DNIe or certificate extraction fails
        """
        if not self.session:
            raise Exception("Not connected to DNIe")
        
        try:
            # Search for certificate objects on the token
            certs = self.session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE
            })
            
            # Return first certificate found
            if certs:
                cert = next(certs)
                cert_data = cert[Attribute.VALUE]
                return bytes(cert_data)
            return None
            
        except Exception as e:
            raise Exception(f"Failed to extract certificate: {str(e)}")
    
    def sign_data(self, data: bytes, mechanism: Mechanism = Mechanism.SHA256_RSA_PKCS) -> bytes:
        """
        Sign data using DNIe's private key.
        
        Args:
            data: Data bytes to sign
            mechanism: PKCS#11 signing mechanism (default: SHA256_RSA_PKCS)
            
        Returns:
            bytes: Digital signature
            
        Raises:
            Exception: If no signing key found or signing operation fails
        """
        if not self.session:
            raise Exception("Not connected to DNIe")
        
        try:
            # Find private keys with signing capability
            private_keys = self.session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.SIGN: True
            })
            
            # Get first available signing key
            priv_key = next(private_keys)
            
            # Perform signing operation
            signature = priv_key.sign(data, mechanism=mechanism)
            return bytes(signature)
            
        except StopIteration:
            raise Exception("No signing key found on DNIe")
        except Exception as e:
            raise Exception(f"Signing failed: {str(e)}")
    
    def verify_signature(self, data: bytes, signature: bytes, certificate: bytes) -> bool:
        """
        Verify signature using certificate's public key.
        
        Args:
            data: Original data that was signed
            signature: Digital signature to verify
            certificate: DER-encoded X.509 certificate
            
        Returns:
            bool: True if signature is valid
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            
            # Load certificate and extract public key
            cert = x509.load_der_x509_certificate(certificate)
            public_key = cert.public_key()
            
            # Verify signature using RSA PKCS#1 v1.5 padding
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
            
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False
    
    def close(self):
        """Close DNIe session to free resources."""
        if self.session:
            self.session.close()
            self.session = None