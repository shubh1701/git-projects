#!/usr/bin/env python3
"""
Security Toolkit - Main Application

A comprehensive cross-platform security toolkit that bundles three essential security tools:
1. Keylogger Detection Tool
2. Password Vault with Encryption
3. Phishing Website Detector

This is the main entry point that provides a unified menu-based interface.
"""

import os
import sys
import platform
import time
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout
from rich.align import Align
from rich import box

# Import our security modules
try:
    from modules.keylogger_detector import KeyloggerDetector
    from modules.password_vault import PasswordVault
    from modules.phishing_detector import PhishingDetector
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are in the 'modules/' directory")
    sys.exit(1)

console = Console()


class SecurityToolkit:
    """Main security toolkit application."""
    
    def __init__(self):
        self.console = console
        self.keylogger_detector = KeyloggerDetector()
        self.password_vault = PasswordVault()
        self.phishing_detector = PhishingDetector()
        
        # Application metadata
        self.app_name = "Security Toolkit"
        self.version = "1.0.0"
        self.author = "Security Toolkit Team"
        
        # Platform information
        self.platform = platform.system()
        self.platform_version = platform.release()
        self.architecture = platform.machine()
        self.python_version = sys.version.split()[0]
    
    def display_banner(self):
        """Display the application banner."""
        banner_text = Text()
        banner_text.append("🔒 ", style="blue")
        banner_text.append("SECURITY TOOLKIT", style="bold blue")
        banner_text.append(" 🔒", style="blue")
        banner_text.append(f"\nVersion {self.version}", style="cyan")
        banner_text.append(f"\nCross-Platform Security Solutions", style="yellow")
        
        banner_panel = Panel(
            Align.center(banner_text),
            title="Welcome",
            border_style="blue",
            box=box.DOUBLE
        )
        console.print(banner_panel)
    
    def display_system_info(self):
        """Display system information."""
        info_text = Text()
        info_text.append(f"Platform: {self.platform} {self.platform_version}\n", style="green")
        info_text.append(f"Architecture: {self.architecture}\n", style="green")
        info_text.append(f"Python: {self.python_version}\n", style="green")
        info_text.append(f"Working Directory: {os.getcwd()}", style="green")
        
        info_panel = Panel(
            info_text,
            title="System Information",
            border_style="green"
        )
        console.print(info_panel)
    
    def display_main_menu(self):
        """Display the main application menu."""
        menu_text = Text()
        menu_text.append("1. ", style="cyan")
        menu_text.append("🔍 Run Keylogger Scan", style="white")
        menu_text.append("\n   Detect suspicious processes that might be keyloggers\n", style="dim")
        
        menu_text.append("2. ", style="cyan")
        menu_text.append("🔐 Open Password Vault", style="white")
        menu_text.append("\n   Manage encrypted credentials securely\n", style="dim")
        
        menu_text.append("3. ", style="cyan")
        menu_text.append("🌐 Check Phishing URL", style="white")
        menu_text.append("\n   Analyze URLs for phishing indicators\n", style="dim")
        
        menu_text.append("4. ", style="cyan")
        menu_text.append("ℹ️  System Information", style="white")
        menu_text.append("\n   View detailed system and security information\n", style="dim")
        
        menu_text.append("5. ", style="cyan")
        menu_text.append("❌ Exit", style="white")
        menu_text.append("\n   Close the Security Toolkit\n", style="dim")
        
        menu_panel = Panel(
            menu_text,
            title="Main Menu",
            border_style="cyan",
            box=box.ROUNDED
        )
        console.print(menu_panel)
    
    def run_keylogger_scan(self):
        """Run the keylogger detection scan."""
        console.print("\n[bold blue]🔍 Starting Keylogger Detection...[/bold blue]")
        
        try:
            # Check if we have sufficient permissions
            if self.platform.lower() == 'windows':
                console.print("[yellow]Note: For best results on Windows, run as Administrator[/yellow]")
            elif self.platform.lower() == 'linux':
                console.print("[yellow]Note: For best results on Linux, run with sudo[/yellow]")
            elif self.platform.lower() == 'darwin':
                console.print("[yellow]Note: Some features may be limited on macOS due to security restrictions[/yellow]")
            
            # Confirm before running scan
            if Confirm.ask("Proceed with keylogger detection scan?"):
                # Run the scan
                suspicious_processes = self.keylogger_detector.run_scan()
                
                # Offer to save results
                if suspicious_processes and Confirm.ask("Save scan results to file?"):
                    self._save_scan_results(suspicious_processes)
                
                return suspicious_processes
            else:
                console.print("[yellow]Keylogger scan cancelled.[/yellow]")
                return []
                
        except Exception as e:
            console.print(f"[bold red]Error during keylogger scan: {str(e)}[/bold red]")
            return []
    
    def open_password_vault(self):
        """Open the password vault interface."""
        console.print("\n[bold blue]🔐 Opening Password Vault...[/bold blue]")
        
        try:
            # Run the vault interface
            success = self.password_vault.run_vault_interface()
            
            if success:
                console.print("[green]Password vault session completed successfully.[/green]")
            else:
                console.print("[yellow]Password vault session ended.[/yellow]")
                
        except Exception as e:
            console.print(f"[bold red]Error with password vault: {str(e)}[/bold red]")
    
    def check_phishing_url(self):
        """Run the phishing URL detector."""
        console.print("\n[bold blue]🌐 Starting Phishing URL Detection...[/bold blue]")
        
        try:
            # Ask user for URL
            url = Prompt.ask("Enter URL to analyze")
            
            if not url:
                console.print("[yellow]No URL provided. Returning to main menu.[/yellow]")
                return
            
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Analyze the URL
            analysis = self.phishing_detector.analyze_url(url)
            
            # Display results
            self.phishing_detector.display_analysis_results(analysis)
            
            # Offer to save results
            if Confirm.ask("Save analysis results to file?"):
                self._save_phishing_analysis(analysis)
                
        except Exception as e:
            console.print(f"[bold red]Error during phishing detection: {str(e)}[/bold red]")
    
    def show_system_information(self):
        """Display comprehensive system information."""
        console.print("\n[bold blue]ℹ️  System Information[/bold blue]")
        
        # Create detailed system info table
        table = Table(title="Detailed System Information")
        table.add_column("Category", style="cyan")
        table.add_column("Details", style="white")
        
        # Platform information
        table.add_row("Operating System", f"{self.platform} {self.platform_version}")
        table.add_row("Architecture", self.architecture)
        table.add_row("Python Version", self.python_version)
        table.add_row("Working Directory", os.getcwd())
        
        # Security-related information
        if self.platform.lower() == 'windows':
            table.add_row("Security Context", "Check if running as Administrator")
        elif self.platform.lower() == 'linux':
            table.add_row("Security Context", "Check if running with sudo")
        elif self.platform.lower() == 'darwin':
            table.add_row("Security Context", "macOS security restrictions may apply")
        
        # File permissions
        try:
            vault_exists = os.path.exists(self.password_vault.vault_file)
            table.add_row("Password Vault", "Exists" if vault_exists else "Not created")
        except:
            table.add_row("Password Vault", "Status unknown")
        
        console.print(table)
        
        # Additional security recommendations
        console.print("\n[bold yellow]Security Recommendations:[/bold yellow]")
        if self.platform.lower() == 'windows':
            console.print("• Run as Administrator for full keylogger detection")
            console.print("• Enable Windows Defender and keep it updated")
            console.print("• Use strong, unique passwords for all accounts")
        elif self.platform.lower() == 'linux':
            console.print("• Run with sudo for complete process access")
            console.print("• Keep system packages updated")
            console.print("• Use firewall and intrusion detection")
        elif self.platform.lower() == 'darwin':
            console.print("• Grant necessary permissions in System Preferences")
            console.print("• Keep macOS updated")
            console.print("• Use FileVault for disk encryption")
        
        console.print("• Regularly scan for suspicious processes")
        console.print("• Use the password vault for secure credential storage")
        console.print("• Always verify URLs before entering credentials")
    
    def _save_scan_results(self, suspicious_processes):
        """Save keylogger scan results to file."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"keylog_scan_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("Keylogger Detection Scan Results\n")
                f.write("=" * 40 + "\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Platform: {self.platform} {self.platform_version}\n")
                f.write(f"Total Suspicious Processes: {len(suspicious_processes)}\n\n")
                
                for proc in suspicious_processes:
                    f.write(f"PID: {proc['pid']}\n")
                    f.write(f"Name: {proc['name']}\n")
                    f.write(f"Executable: {proc['exe']}\n")
                    f.write(f"Suspicion Score: {proc['suspicion_score']}/100\n")
                    f.write(f"Reasons: {', '.join(proc['reasons'])}\n")
                    f.write("-" * 30 + "\n")
            
            console.print(f"[green]Scan results saved to: {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error saving scan results: {str(e)}[/red]")
    
    def _save_phishing_analysis(self, analysis):
        """Save phishing analysis results to file."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"phishing_analysis_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write("Phishing URL Analysis Results\n")
                f.write("=" * 35 + "\n")
                f.write(f"Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"URL: {analysis['url']}\n")
                f.write(f"Risk Score: {analysis['risk_score']}/100\n")
                f.write(f"Risk Level: {analysis['risk_level']}\n\n")
                
                if analysis['issues']:
                    f.write("Issues Found:\n")
                    for issue in analysis['issues']:
                        f.write(f"• {issue}\n")
                    f.write("\n")
                
                if analysis['details']:
                    f.write("URL Details:\n")
                    for key, value in analysis['details'].items():
                        if value:
                            f.write(f"• {key}: {value}\n")
            
            console.print(f"[green]Analysis results saved to: {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error saving analysis results: {str(e)}[/red]")
    
    def run(self):
        """Run the main application loop."""
        try:
            # Clear screen and display banner
            os.system('cls' if os.name == 'nt' else 'clear')
            self.display_banner()
            
            # Display system information
            self.display_system_info()
            
            # Main application loop
            while True:
                try:
                    # Display main menu
                    self.display_main_menu()
                    
                    # Get user choice
                    choice = Prompt.ask(
                        "Choose an option",
                        choices=["1", "2", "3", "4", "5"],
                        default="5"
                    )
                    
                    # Process user choice
                    if choice == "1":
                        self.run_keylogger_scan()
                    elif choice == "2":
                        self.open_password_vault()
                    elif choice == "3":
                        self.check_phishing_url()
                    elif choice == "4":
                        self.show_system_information()
                    elif choice == "5":
                        if Confirm.ask("Are you sure you want to exit?"):
                            console.print("\n[green]Thank you for using Security Toolkit![/green]")
                            console.print("[green]Stay safe and secure! 🔒[/green]")
                            break
                    
                    # Pause before showing menu again
                    if choice != "5":
                        console.print("\n[dim]Press Enter to continue...[/dim]")
                        input()
                        os.system('cls' if os.name == 'nt' else 'clear')
                        self.display_banner()
                
                except KeyboardInterrupt:
                    console.print("\n\n[yellow]Interrupted by user. Returning to main menu...[/yellow]")
                    time.sleep(2)
                    continue
                
                except Exception as e:
                    console.print(f"\n[bold red]Unexpected error: {str(e)}[/bold red]")
                    console.print("[yellow]Returning to main menu...[/yellow]")
                    time.sleep(3)
                    continue
        
        except Exception as e:
            console.print(f"[bold red]Critical error: {str(e)}[/bold red]")
            console.print("[red]Application will exit.[/red]")
            sys.exit(1)


def main():
    """Main entry point."""
    try:
        # Check Python version
        if sys.version_info < (3, 8):
            print("Error: Python 3.8 or higher is required.")
            print(f"Current version: {sys.version}")
            sys.exit(1)
        
        # Create and run the toolkit
        toolkit = SecurityToolkit()
        toolkit.run()
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
