# cli.py - Interfaz de línea de comandos con autenticación DNIe integrada
import click
import getpass
from crypto import CryptoManager

@click.group()
def cli():
    """Password Manager secured by DNIe"""
    pass

@cli.command()
def init():
    """Initialize password manager with DNIe"""
    try:
        crypto = CryptoManager()
        crypto.initialize_db()
        click.echo("✅ Password manager initialized successfully with DNIe!")
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.option('--service', prompt='Service')
@click.option('--username', prompt='Username')
@click.option('--password', prompt=True, hide_input=True)
def add(service, username, password):
    """Add password entry using DNIe authentication"""
    try:
        crypto = CryptoManager()
        crypto.add_password(service, username, password)
        click.echo("✅ Password added successfully!")
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def list():
    """List all password entries using DNIe authentication"""
    try:
        crypto = CryptoManager()
        entries = crypto.list_entries()
        
        if not entries:
            click.echo("📭 No password entries found")
        else:
            click.echo("🔐 Stored passwords:")
            for entry in entries:
                click.echo(f"  Service: {entry['service']}")
                click.echo(f"  Username: {entry['username']}")
                click.echo("  " + "-" * 30)
            
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def status():
    """Check DNIe status and connection"""
    try:
        from dnie import DNIeManager
        import pkcs11
        
        dnie = DNIeManager()
        dnie._lib = pkcs11.lib(dnie.lib_path)
        slots = dnie._lib.get_slots(token_present=True)
        
        if slots:
            token = slots[0].get_token()
            click.echo("✅ DNIe Information:")
            click.echo(f"   Label: {token.label}")
            click.echo(f"   Manufacturer: {token.manufacturer_id}")
            click.echo(f"   Model: {token.model}")
            click.echo("   Status: Ready for authentication")
        else:
            click.echo("❌ No DNIe detected - please insert your DNIe card")
            
    except Exception as e:
        click.echo(f"❌ Error accessing DNIe: {str(e)}")

if __name__ == '__main__':
    cli()