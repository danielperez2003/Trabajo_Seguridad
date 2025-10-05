"Interfaz por linea de comandos"
import click
import getpass
from .crypto import CryptoManager
from .dnie import DNIeManager

@click.group()
def cli():
    """Password Manager secured by DNIe"""
    pass

@cli.command()
def init():
    """Initialize password manager with DNIe"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        dnie = DNIeManager()
        key = dnie.authenticate(pin)
        
        crypto = CryptoManager()
        crypto.initialize_db(key)
        
        click.echo("✅ Password manager initialized successfully!")
        dnie.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.option('--service', prompt='Service')
@click.option('--username', prompt='Username')
@click.option('--password', prompt=True, hide_input=True)
def add(service, username, password):
    """Add password entry"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        dnie = DNIeManager()
        key = dnie.authenticate(pin)
        
        crypto = CryptoManager()
        crypto.fernet = crypto.fernet.__class__(key)
        crypto.add_password(service, username, password)
        
        click.echo("✅ Password added successfully!")
        dnie.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def list():
    """List all password entries"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        dnie = DNIeManager()
        key = dnie.authenticate(pin)
        
        crypto = CryptoManager()
        crypto.fernet = crypto.fernet.__class__(key)
        entries = crypto.list_entries()
        
        for entry in entries:
            click.echo(f"Service: {entry['service']}, Username: {entry['username']}")
            
        dnie.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

if __name__ == '__main__':
    cli()