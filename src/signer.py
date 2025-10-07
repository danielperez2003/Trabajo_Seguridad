import hashlib
import json
import base64
from pathlib import Path
from typing import Dict, Any
from .dnie_client import DNIeClient

class FileSigner:
    def __init__(self):
        """Initialize file signer with DNIe client."""
        self.dnie = DNIeClient()
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate cryptographic hash of file content.
        
        Args:
            file_path: Path to file to hash
            algorithm: Hash algorithm (default: 'sha256')
            
        Returns:
            str: Hexadecimal hash digest
        """
        # Get hash function from hashlib
        hash_func = getattr(hashlib, algorithm)()
        
        # Read file in chunks to handle large files efficiently
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def sign_file(self, file_path: str, pin: str, output_path: str = None) -> Dict[str, Any]:
        """
        Sign a file and create detached signature file.
        
        Args:
            file_path: Path to file to sign
            pin: DNIe PIN
            output_path: Optional path for signature file
            
        Returns:
            Dict: Signature package with file info and signature
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            Exception: If signing fails
        """
        if not Path(file_path).exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Authenticate with DNIe
        self.dnie.connect(pin)
        
        try:
            # Calculate file hash for integrity checking
            file_hash = self.calculate_file_hash(file_path)
            
            # Read entire file content for signing
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Create digital signature using DNIe
            signature = self.dnie.sign_data(file_data)
            
            # Extract certificate for verification
            certificate = self.dnie.get_certificate()
            
            # Create signature package with metadata
            signature_package = {
                'file_path': str(Path(file_path).absolute()),
                'file_hash': file_hash,
                'hash_algorithm': 'sha256',
                'signature': base64.b64encode(signature).decode('utf-8'),
                'certificate': base64.b64encode(certificate).decode('utf-8') if certificate else None,
                'timestamp': None  # Placeholder for timestamp functionality
            }
            
            # Determine output path for signature file
            if output_path is None:
                output_path = f"{file_path}.signature"
            
            # Save signature package as JSON
            with open(output_path, 'w') as f:
                json.dump(signature_package, f, indent=2)
            
            return signature_package
            
        finally:
            # Ensure DNIe session is always closed
            self.dnie.close()
    
    def verify_signature(self, file_path: str, signature_path: str) -> bool:
        """
        Verify file signature against original file.
        
        Args:
            file_path: Path to original file
            signature_path: Path to signature file
            
        Returns:
            bool: True if signature is valid and file unchanged
            
        Raises:
            FileNotFoundError: If files are missing
        """
        if not Path(file_path).exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not Path(signature_path).exists():
            raise FileNotFoundError(f"Signature file not found: {signature_path}")
        
        try:
            # Load signature package from file
            with open(signature_path, 'r') as f:
                signature_package = json.load(f)
            
            # Verify file integrity by comparing hashes
            current_hash = self.calculate_file_hash(file_path, signature_package['hash_algorithm'])
            if current_hash != signature_package['file_hash']:
                print("File has been modified since signing!")
                return False
            
            # Read file content for signature verification
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Decode signature and certificate from base64
            signature = base64.b64decode(signature_package['signature'])
            certificate = base64.b64decode(signature_package['certificate'])
            
            # Verify digital signature
            self.dnie.connect('')  # Empty PIN for read-only operations
            is_valid = self.dnie.verify_signature(file_data, signature, certificate)
            self.dnie.close()
            
            return is_valid
            
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False
    
    def export_certificate(self, pin: str, output_path: str = "dnie_certificate.der") -> str:
        """
        Export DNIe certificate to file.
        
        Args:
            pin: DNIe PIN
            output_path: Path for certificate file
            
        Returns:
            str: Path to exported certificate file
        """
        self.dnie.connect(pin)
        
        try:
            certificate = self.dnie.get_certificate()
            if not certificate:
                raise Exception("No certificate found on DNIe")
            
            # Save certificate as DER file
            with open(output_path, 'wb') as f:
                f.write(certificate)
            
            return output_path
            
        finally:
            self.dnie.close()