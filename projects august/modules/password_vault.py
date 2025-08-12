"""
Password Vault with Encryption

Secure password storage using the cryptography library with Fernet encryption.
Features: add, retrieve, delete, and search credentials with master password protection.
"""

import os
import json
import base64
import getpass
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.syntax import Syntax

console = Console()


class PasswordVault:
    """Encrypted password vault with master password protection."""
    
    def __init__(self, vault_file: str = "vault.enc", salt_file: str = "vault.salt"):
        self.vault_file = vault_file
        self.salt_file = salt_file
        self.fernet = None
        self.is_unlocked = False
        self.credentials = {}
        
        # Ensure vault directory exists
        os.makedirs(os.path.dirname(vault_file) if os.path.dirname(vault_file) else ".", exist_ok=True)
    
    def _generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _generate_salt(self) -> bytes:
        """Generate a random salt for key derivation."""
        return os.urandom(16)
    
    def _load_salt(self) -> Optional[bytes]:
        """Load existing salt from file."""
        try:
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'rb') as f:
                    return f.read()
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load salt file: {e}[/yellow]")
        return None
    
    def _save_salt(self, salt: bytes):
        """Save salt to file."""
        try:
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        except Exception as e:
            console.print(f"[red]Error saving salt file: {e}[/red]")
    
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt data using Fernet."""
        if not self.fernet:
            raise ValueError("Vault is not unlocked")
        return self.fernet.encrypt(data.encode())
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data using Fernet."""
        if not self.fernet:
            raise ValueError("Vault is not unlocked")
        return self.fernet.decrypt(encrypted_data).decode()
    
    def _save_vault(self):
        """Save encrypted credentials to vault file."""
        try:
            encrypted_data = self._encrypt_data(json.dumps(self.credentials))
            with open(self.vault_file, 'wb') as f:
                f.write(encrypted_data)
            console.print("[green]Vault saved successfully![/green]")
        except Exception as e:
            console.print(f"[red]Error saving vault: {e}[/red]")
    
    def _load_vault(self) -> bool:
        """Load encrypted credentials from vault file."""
        try:
            if not os.path.exists(self.vault_file):
                return True  # New vault, nothing to load
            
            with open(self.vault_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._decrypt_data(encrypted_data)
            self.credentials = json.loads(decrypted_data)
            return True
            
        except Exception as e:
            console.print(f"[red]Error loading vault: {e}[/red]")
            return False
    
    def setup_master_password(self) -> bool:
        """Set up master password for new vault."""
        console.print("\n[bold blue]🔐 Setting up Master Password[/bold blue]")
        console.print("This will be used to encrypt and decrypt your password vault.")
        
        while True:
            master_password = getpass.getpass("Enter master password: ")
            if len(master_password) < 8:
                console.print("[red]Password must be at least 8 characters long![/red]")
                continue
            
            confirm_password = getpass.getpass("Confirm master password: ")
            if master_password != confirm_password:
                console.print("[red]Passwords do not match![/red]")
                continue
            
            break
        
        # Generate salt and key
        salt = self._generate_salt()
        key = self._generate_key_from_password(master_password, salt)
        
        # Save salt and initialize Fernet
        self._save_salt(salt)
        self.fernet = Fernet(key)
        self.is_unlocked = True
        
        console.print("[green]Master password set successfully![/green]")
        return True
    
    def unlock_vault(self) -> bool:
        """Unlock vault with master password."""
        if self.is_unlocked:
            return True
        
        console.print("\n[bold blue]🔓 Unlocking Password Vault[/bold blue]")
        
        # Load existing salt
        salt = self._load_salt()
        if not salt:
            console.print("[red]No existing vault found. Please set up a master password first.[/red]")
            return False
        
        # Try to unlock with password
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                master_password = getpass.getpass(f"Enter master password (attempt {attempt + 1}/{max_attempts}): ")
                key = self._generate_key_from_password(master_password, salt)
                self.fernet = Fernet(key)
                
                # Test decryption by trying to load the vault
                if self._load_vault():
                    self.is_unlocked = True
                    console.print("[green]Vault unlocked successfully![/green]")
                    return True
                else:
                    console.print("[red]Invalid master password![/red]")
                    
            except Exception as e:
                console.print(f"[red]Error unlocking vault: {e}[/red]")
        
        console.print("[red]Failed to unlock vault after maximum attempts![/red]")
        return False
    
    def add_credential(self, service: str, username: str, password: str, notes: str = ""):
        """Add a new credential to the vault."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return False
        
        # Generate unique ID for the credential
        import uuid
        import time
        cred_id = str(uuid.uuid4())
        
        credential = {
            'id': cred_id,
            'service': service,
            'username': username,
            'password': password,
            'notes': notes,
            'created': str(os.path.getctime(self.vault_file) if os.path.exists(self.vault_file) else time.time()),
            'modified': str(time.time())
        }
        
        self.credentials[cred_id] = credential
        self._save_vault()
        
        console.print(f"[green]Credential for {service} added successfully![/green]")
        return True
    
    def get_credential(self, cred_id: str) -> Optional[Dict]:
        """Get a specific credential by ID."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return None
        
        return self.credentials.get(cred_id)
    
    def search_credentials(self, query: str) -> List[Dict]:
        """Search credentials by service name or username."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return []
        
        query_lower = query.lower()
        results = []
        
        for cred in self.credentials.values():
            if (query_lower in cred['service'].lower() or 
                query_lower in cred['username'].lower() or
                query_lower in cred['notes'].lower()):
                results.append(cred)
        
        return results
    
    def list_credentials(self) -> List[Dict]:
        """List all credentials in the vault."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return []
        
        return list(self.credentials.values())
    
    def delete_credential(self, cred_id: str) -> bool:
        """Delete a credential from the vault."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return False
        
        if cred_id in self.credentials:
            service_name = self.credentials[cred_id]['service']
            del self.credentials[cred_id]
            self._save_vault()
            console.print(f"[green]Credential for {service_name} deleted successfully![/green]")
            return True
        else:
            console.print("[red]Credential not found![/red]")
            return False
    
    def update_credential(self, cred_id: str, **kwargs) -> bool:
        """Update a credential in the vault."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return False
        
        if cred_id in self.credentials:
            # Update only allowed fields
            allowed_fields = ['service', 'username', 'password', 'notes']
            for field, value in kwargs.items():
                if field in allowed_fields:
                    self.credentials[cred_id][field] = value
            
            self.credentials[cred_id]['modified'] = str(time.time())
            self._save_vault()
            console.print(f"[green]Credential updated successfully![/green]")
            return True
        else:
            console.print("[red]Credential not found![/red]")
            return False
    
    def display_credentials(self, credentials: List[Dict], title: str = "Credentials"):
        """Display credentials in a formatted table."""
        if not credentials:
            console.print(f"\n[yellow]No {title.lower()} found.[/yellow]")
            return
        
        table = Table(title=title)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Service", style="magenta")
        table.add_column("Username", style="blue")
        table.add_column("Password", style="red")
        table.add_column("Notes", style="yellow")
        table.add_column("Modified", style="green")
        
        for cred in credentials:
            # Truncate long values for display
            service = cred['service'][:20] + "..." if len(cred['service']) > 20 else cred['service']
            username = cred['username'][:20] + "..." if len(cred['username']) > 20 else cred['username']
            password = "*" * min(len(cred['password']), 10)
            notes = cred['notes'][:30] + "..." if len(cred['notes']) > 30 else cred['notes']
            
            # Format timestamp
            try:
                import time
                timestamp = float(cred['modified'])
                modified = time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))
            except:
                modified = "Unknown"
            
            table.add_row(
                cred['id'][:8] + "...",
                service,
                username,
                password,
                notes,
                modified
            )
        
        console.print(table)
    
    def show_credential_details(self, cred_id: str):
        """Show detailed information for a specific credential."""
        if not self.is_unlocked:
            console.print("[red]Vault is not unlocked![/red]")
            return
        
        credential = self.get_credential(cred_id)
        if not credential:
            console.print("[red]Credential not found![/red]")
            return
        
        # Create detailed view
        details_text = Text()
        details_text.append(f"Service: {credential['service']}\n", style="magenta")
        details_text.append(f"Username: {credential['username']}\n", style="blue")
        details_text.append(f"Password: {credential['password']}\n", style="red")
        details_text.append(f"Notes: {credential['notes']}\n", style="yellow")
        details_text.append(f"Created: {credential['created']}\n", style="green")
        details_text.append(f"Modified: {credential['modified']}\n", style="green")
        details_text.append(f"ID: {credential['id']}", style="cyan")
        
        details_panel = Panel(details_text, title="Credential Details", border_style="blue")
        console.print(details_panel)
    
    def run_vault_interface(self):
        """Run the interactive vault interface."""
        console.print("\n[bold blue]🔐 Password Vault Interface[/bold blue]")
        
        # Check if vault exists and unlock/setup
        if os.path.exists(self.vault_file):
            if not self.unlock_vault():
                return False
        else:
            if not self.setup_master_password():
                return False
        
        while True:
            console.print("\n[bold cyan]Vault Menu:[/bold cyan]")
            console.print("1. Add Credential")
            console.print("2. View All Credentials")
            console.print("3. Search Credentials")
            console.print("4. View Credential Details")
            console.print("5. Update Credential")
            console.print("6. Delete Credential")
            console.print("7. Exit Vault")
            
            choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5", "6", "7"])
            
            if choice == "1":
                self._add_credential_interface()
            elif choice == "2":
                self._view_all_credentials_interface()
            elif choice == "3":
                self._search_credentials_interface()
            elif choice == "4":
                self._view_credential_details_interface()
            elif choice == "5":
                self._update_credential_interface()
            elif choice == "6":
                self._delete_credential_interface()
            elif choice == "7":
                console.print("[green]Exiting vault...[/green]")
                break
        
        return True
    
    def _add_credential_interface(self):
        """Interface for adding a new credential."""
        console.print("\n[bold blue]➕ Add New Credential[/bold blue]")
        
        service = Prompt.ask("Service name")
        username = Prompt.ask("Username")
        password = getpass.getpass("Password: ")
        notes = Prompt.ask("Notes (optional)", default="")
        
        if Confirm.ask(f"Add credential for {service}?"):
            self.add_credential(service, username, password, notes)
    
    def _view_all_credentials_interface(self):
        """Interface for viewing all credentials."""
        console.print("\n[bold blue]📋 All Credentials[/bold blue]")
        credentials = self.list_credentials()
        self.display_credentials(credentials, "All Credentials")
    
    def _search_credentials_interface(self):
        """Interface for searching credentials."""
        console.print("\n[bold blue]🔍 Search Credentials[/bold blue]")
        query = Prompt.ask("Enter search term")
        results = self.search_credentials(query)
        self.display_credentials(results, f"Search Results for '{query}'")
    
    def _view_credential_details_interface(self):
        """Interface for viewing credential details."""
        console.print("\n[bold blue]👁️  View Credential Details[/bold blue]")
        cred_id = Prompt.ask("Enter credential ID (first 8 characters)")
        
        # Find credential by partial ID
        for full_id in self.credentials.keys():
            if full_id.startswith(cred_id):
                self.show_credential_details(full_id)
                return
        
        console.print("[red]Credential not found![/red]")
    
    def _update_credential_interface(self):
        """Interface for updating a credential."""
        console.print("\n[bold blue]✏️  Update Credential[/bold blue]")
        cred_id = Prompt.ask("Enter credential ID (first 8 characters)")
        
        # Find credential by partial ID
        target_id = None
        for full_id in self.credentials.keys():
            if full_id.startswith(cred_id):
                target_id = full_id
                break
        
        if not target_id:
            console.print("[red]Credential not found![/red]")
            return
        
        credential = self.get_credential(target_id)
        console.print(f"Current service: {credential['service']}")
        
        updates = {}
        if Confirm.ask("Update service name?"):
            updates['service'] = Prompt.ask("New service name")
        if Confirm.ask("Update username?"):
            updates['username'] = Prompt.ask("New username")
        if Confirm.ask("Update password?"):
            updates['password'] = getpass.getpass("New password: ")
        if Confirm.ask("Update notes?"):
            updates['notes'] = Prompt.ask("New notes")
        
        if updates:
            self.update_credential(target_id, **updates)
    
    def _delete_credential_interface(self):
        """Interface for deleting a credential."""
        console.print("\n[bold blue]🗑️  Delete Credential[/bold blue]")
        cred_id = Prompt.ask("Enter credential ID (first 8 characters)")
        
        # Find credential by partial ID
        target_id = None
        for full_id in self.credentials.keys():
            if full_id.startswith(cred_id):
                target_id = full_id
                break
        
        if not target_id:
            console.print("[red]Credential not found![/red]")
            return
        
        credential = self.get_credential(target_id)
        if Confirm.ask(f"Are you sure you want to delete credential for {credential['service']}?"):
            self.delete_credential(target_id)


if __name__ == "__main__":
    # Test the vault
    import time
    vault = PasswordVault()
    vault.run_vault_interface()
