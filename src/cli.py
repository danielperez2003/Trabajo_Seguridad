"Comandos de línea de comandos para firmar y verificar archivos usando DNIe"
import click
import getpass
from pathlib import Path
import sys
import os

# Add src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from .signer import FileSigner
    from .dnie_client import DNIeClient
    import pkcs11
    HAS_DEPENDENCIES = True
except ImportError as e:
    print(f"Warning: Some dependencies missing - {e}")
    HAS_DEPENDENCIES = False

@click.group()
def cli():
    """DNIe File Signer - Sign and verify files using your DNIe smart card"""
    pass

@cli.command()
@click.argument('file_path')
@click.option('--output', '-o', help='Output signature file path')
def sign(file_path, output):
    """
    Sign a file using DNIe smart card.
    
    FILE_PATH: Path to the file you want to sign
    """
    if not HAS_DEPENDENCIES:
        click.echo("Error: Required dependencies not available")
        sys.exit(1)
        
    try:
        # Validate file exists
        if not Path(file_path).exists():
            click.echo(f"Error: File not found: {file_path}")
            return
            
        # Securely read PIN without echo
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        # Sign the file
        signer = FileSigner()
        result = signer.sign_file(file_path, pin, output)
        
        output_path = output or f"{file_path}.signature"
        click.echo("File signed successfully")
        click.echo(f"Signature saved to: {output_path}")
        click.echo(f"File hash: {result['file_hash']}")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
@click.argument('file_path')
@click.argument('signature_path')
def verify(file_path, signature_path):
    """
    Verify file signature against original file.
    
    FILE_PATH: Path to the original file
    SIGNATURE_PATH: Path to the signature file
    """
    if not HAS_DEPENDENCIES:
        click.echo("Error: Required dependencies not available")
        sys.exit(1)
        
    try:
        # Validate files exist
        if not Path(file_path).exists():
            click.echo(f"Error: File not found: {file_path}")
            return
        if not Path(signature_path).exists():
            click.echo(f"Error: Signature file not found: {signature_path}")
            return
            
        # Verify the signature
        signer = FileSigner()
        is_valid = signer.verify_signature(file_path, signature_path)
        
        if is_valid:
            click.echo("Signature is VALID - File is authentic and unchanged")
        else:
            click.echo("Signature is INVALID - File may have been tampered with")
            
    except Exception as e:
        click.echo(f"Verification error: {str(e)}")

@cli.command()
@click.option('--output', '-o', default='dnie_certificate.der', 
              help='Output certificate file path')
def export_cert(output):
    """
    Export DNIe certificate to file.
    """
    if not HAS_DEPENDENCIES:
        click.echo("Error: Required dependencies not available")
        sys.exit(1)
        
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        signer = FileSigner()
        cert_path = signer.export_certificate(pin, output)
        
        click.echo(f"Certificate exported to: {cert_path}")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
def info():
    """Display DNIe smart card information and status"""
    try:
        if not HAS_DEPENDENCIES:
            click.echo("Error: Required dependencies not available")
            return
            
        dnie = DNIeClient()
        dnie._lib = pkcs11.lib(dnie.lib_path)
        slots = dnie._lib.get_slots(token_present=True)
        
        if slots:
            token = slots[0].get_token()
            click.echo("DNIe Information:")
            click.echo(f"  Label: {token.label}")
            click.echo(f"  Manufacturer: {token.manufacturer_id}")
            click.echo(f"  Model: {token.model}")
            click.echo("Status: DNIe is ready for use")
        else:
            click.echo("Status: No DNIe detected - please insert your DNIe card")
            
    except Exception as e:
        click.echo(f"Error accessing DNIe: {str(e)}")

@cli.command()
def test():
    """Test DNIe connection and basic cryptographic operations"""
    if not HAS_DEPENDENCIES:
        click.echo("Error: Required dependencies not available")
        sys.exit(1)
        
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        dnie = DNIeClient()
        dnie.connect(pin)
        
        click.echo("Testing DNIe operations:")
        
        # Test certificate extraction
        certificate = dnie.get_certificate()
        if certificate:
            click.echo("  ✓ Certificate extraction: SUCCESS")
        else:
            click.echo("  ✗ Certificate extraction: FAILED")
        
        # Test signing capability
        test_data = b"test_signature_data_12345"
        try:
            signature = dnie.sign_data(test_data)
            click.echo("  ✓ Signing capability: SUCCESS")
            
            # Test verification
            if dnie.verify_signature(test_data, signature, certificate):
                click.echo("  ✓ Signature verification: SUCCESS")
            else:
                click.echo("  ✗ Signature verification: FAILED")
                
        except Exception as e:
            click.echo(f"  ✗ Signing capability: FAILED - {str(e)}")
        
        dnie.close()
        click.echo("DNIe test completed successfully")
        
    except Exception as e:
        click.echo(f"DNIe test failed: {str(e)}")

@cli.command()
@click.argument('file_path')
@click.option('--algorithm', '-a', default='sha256', 
              help='Hash algorithm (sha256, sha384, sha512)')
def hash(file_path, algorithm):
    """
    Calculate cryptographic hash of a file.
    
    FILE_PATH: Path to the file to hash
    """
    try:
        if not Path(file_path).exists():
            click.echo(f"Error: File not found: {file_path}")
            return
            
        signer = FileSigner()
        file_hash = signer.calculate_file_hash(file_path, algorithm)
        
        click.echo(f"File: {file_path}")
        click.echo(f"Algorithm: {algorithm.upper()}")
        click.echo(f"Hash: {file_hash}")
        
    except Exception as e:
        click.echo(f"Error calculating hash: {str(e)}")

@cli.command()
def version():
    """Show version information"""
    click.echo("DNIe File Signer v1.0.0")
    click.echo("File signing and verification using DNIe smart card")

# Main entry point with comprehensive error handling
def main():
    """Main entry point for the CLI application"""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()