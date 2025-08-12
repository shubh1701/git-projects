#!/usr/bin/env python3
"""
Security Toolkit Demo Script

This script demonstrates the capabilities of the Security Toolkit
without requiring actual system access or user interaction.
"""

import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


def demo_banner():
    """Display demo banner."""
    banner_text = Text()
    banner_text.append("🔒 ", style="blue")
    banner_text.append("SECURITY TOOLKIT DEMO", style="bold blue")
    banner_text.append(" 🔒", style="blue")
    banner_text.append(f"\nDemonstrating Security Features", style="yellow")
    banner_text.append(f"\n(No actual system access required)", style="dim")
    
    banner_panel = Panel(
        banner_text,
        title="Demo Mode",
        border_style="blue",
        box=box.DOUBLE
    )
    console.print(banner_panel)


def demo_keylogger_detection():
    """Demonstrate keylogger detection capabilities."""
    console.print("\n[bold blue]🔍 Keylogger Detection Demo[/bold blue]")
    
    # Sample suspicious processes
    sample_processes = [
        {
            'pid': 1234,
            'name': 'keylogger.exe',
            'exe': 'C:\\temp\\keylogger.exe',
            'suspicion_score': 85,
            'reasons': ['Known suspicious process name', 'High CPU usage: 75.2%']
        },
        {
            'pid': 5678,
            'name': 'monitor.exe',
            'exe': 'C:\\temp\\monitor.exe',
            'suspicion_score': 65,
            'reasons': ['Contains suspicious keyword: monitor', 'Network connection to private IP: 192.168.1.100']
        },
        {
            'pid': 9012,
            'name': 'hook.dll',
            'exe': 'C:\\temp\\hook.dll',
            'suspicion_score': 55,
            'reasons': ['Contains suspicious keyword: hook', 'Suspicious DLL loaded']
        }
    ]
    
    # Display results
    console.print(f"\n[bold red]⚠️  Found {len(sample_processes)} suspicious processes:[/bold red]")
    
    table = Table(title="Keylogger Detection Results (Demo)")
    table.add_column("PID", style="cyan", no_wrap=True)
    table.add_column("Process Name", style="magenta")
    table.add_column("Suspicion Score", style="red")
    table.add_column("Reasons", style="yellow")
    table.add_column("Executable", style="blue")
    
    for proc in sample_processes:
        reasons_text = "\n".join(proc['reasons'])
        table.add_row(
            str(proc['pid']),
            proc['name'],
            f"{proc['suspicion_score']}/100",
            reasons_text,
            proc['exe']
        )
    
    console.print(table)
    
    # Summary
    total_score = sum(proc['suspicion_score'] for proc in sample_processes)
    avg_score = total_score / len(sample_processes)
    
    summary_text = Text()
    summary_text.append(f"Total Processes Scanned: {len(sample_processes)}\n", style="blue")
    summary_text.append(f"Average Suspicion Score: {avg_score:.1f}/100\n", style="yellow")
    summary_text.append(f"Highest Risk Process: {sample_processes[0]['name']} (PID: {sample_processes[0]['pid']})", style="red")
    
    summary_panel = Panel(summary_text, title="Scan Summary", border_style="blue")
    console.print(summary_panel)


def demo_password_vault():
    """Demonstrate password vault capabilities."""
    console.print("\n[bold blue]🔐 Password Vault Demo[/bold blue]")
    
    # Sample credentials
    sample_credentials = [
        {
            'id': 'abc12345...',
            'service': 'Gmail',
            'username': 'user@gmail.com',
            'password': '**********',
            'notes': 'Personal email account',
            'modified': '2024-01-15 14:30'
        },
        {
            'id': 'def67890...',
            'service': 'PayPal',
            'username': 'user@paypal.com',
            'password': '**********',
            'notes': 'Online payments',
            'modified': '2024-01-10 09:15'
        },
        {
            'id': 'ghi11111...',
            'service': 'GitHub',
            'username': 'developer',
            'password': '**********',
            'notes': 'Code repository access',
            'modified': '2024-01-12 16:45'
        }
    ]
    
    # Display credentials
    table = Table(title="Password Vault Contents (Demo)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Service", style="magenta")
    table.add_column("Username", style="blue")
    table.add_column("Password", style="red")
    table.add_column("Notes", style="yellow")
    table.add_column("Modified", style="green")
    
    for cred in sample_credentials:
        table.add_row(
            cred['id'],
            cred['service'],
            cred['username'],
            cred['password'],
            cred['notes'],
            cred['modified']
        )
    
    console.print(table)
    
    # Security features
    security_text = Text()
    security_text.append("🔒 ", style="green")
    security_text.append("Military-grade AES-256 encryption\n", style="green")
    security_text.append("🔑 ", style="green")
    security_text.append("Master password protection\n", style="green")
    security_text.append("🔄 ", style="green")
    security_text.append("PBKDF2 key derivation (100,000 iterations)\n", style="green")
    security_text.append("💾 ", style="green")
    security_text.append("Secure file storage with salt\n", style="green")
    security_text.append("🔍 ", style="green")
    security_text.append("Search and filter capabilities", style="green")
    
    security_panel = Panel(security_text, title="Security Features", border_style="green")
    console.print(security_panel)


def demo_phishing_detection():
    """Demonstrate phishing detection capabilities."""
    console.print("\n[bold blue]🌐 Phishing Detection Demo[/bold blue]")
    
    # Sample phishing URLs and analysis
    sample_analyses = [
        {
            'url': 'http://fake-paypal.com/login',
            'risk_score': 85,
            'risk_level': 'CRITICAL',
            'issues': [
                'Uses HTTP instead of HTTPS (insecure)',
                'Possible typosquatting of paypal',
                'Suspicious keywords found: login'
            ]
        },
        {
            'url': 'https://192.168.1.100/secure-banking',
            'risk_score': 95,
            'risk_level': 'CRITICAL',
            'issues': [
                'Domain is an IP address instead of a domain name',
                'IP address is in private range',
                'Suspicious keywords found: secure, banking'
            ]
        },
        {
            'url': 'https://g00gle-secure-login.xyz/verify',
            'risk_score': 75,
            'risk_level': 'HIGH',
            'issues': [
                'Possible typosquatting of google',
                'Suspicious TLD: .xyz',
                'Suspicious keywords found: secure, login, verify'
            ]
        }
    ]
    
    # Display analyses
    for analysis in sample_analyses:
        # Risk level with color coding
        risk_colors = {
            'SAFE': 'green',
            'LOW': 'yellow',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'red'
        }
        
        risk_color = risk_colors.get(analysis['risk_level'], 'white')
        
        # Results panel
        results_text = Text()
        results_text.append(f"URL: {analysis['url']}\n", style="blue")
        results_text.append(f"Risk Score: {analysis['risk_score']}/100\n", style=risk_color)
        results_text.append(f"Risk Level: {analysis['risk_level']}\n", style=risk_color)
        
        results_panel = Panel(results_text, title="Analysis Results", border_style=risk_color)
        console.print(results_panel)
        
        # Issues table
        if analysis['issues']:
            console.print(f"\n[bold red]⚠️  Issues Found ({len(analysis['issues'])}):[/bold red]")
            
            issues_table = Table(title="Detected Issues")
            issues_table.add_column("Issue", style="red")
            issues_table.add_column("Risk Impact", style="yellow")
            
            for issue in analysis['issues']:
                # Determine risk impact based on issue type
                if 'IP address' in issue:
                    impact = "High"
                elif 'HTTP' in issue or 'typosquatting' in issue:
                    impact = "Medium"
                elif 'keyword' in issue or 'TLD' in issue:
                    impact = "Low"
                else:
                    impact = "Medium"
                
                issues_table.add_row(issue, impact)
            
            console.print(issues_table)
        
        console.print("\n" + "─" * 60 + "\n")


def demo_cross_platform():
    """Demonstrate cross-platform capabilities."""
    console.print("\n[bold blue]🖥️  Cross-Platform Support Demo[/bold blue]")
    
    # Platform-specific features
    platforms = {
        'Windows': [
            'Process monitoring with psutil',
            'DLL analysis and network connection checking',
            'Registry monitoring capabilities',
            'Windows-specific suspicious process detection'
        ],
        'Linux': [
            '/proc filesystem analysis',
            '/dev/input device access detection',
            'File descriptor monitoring',
            'Network socket analysis'
        ],
        'macOS': [
            'Process monitoring within permission limits',
            'Network activity analysis',
            'File system monitoring',
            'Security framework integration'
        ]
    }
    
    for platform_name, features in platforms.items():
        feature_text = Text()
        for feature in features:
            feature_text.append(f"• {feature}\n", style="green")
        
        platform_panel = Panel(
            feature_text,
            title=f"{platform_name} Features",
            border_style="cyan"
        )
        console.print(platform_panel)


def demo_security_features():
    """Demonstrate overall security features."""
    console.print("\n[bold blue]🛡️  Security Features Overview[/bold blue]")
    
    features_table = Table(title="Security Toolkit Features")
    features_table.add_column("Feature", style="cyan")
    features_table.add_column("Description", style="white")
    features_table.add_column("Benefit", style="green")
    
    features = [
        ("Cross-Platform", "Works on Windows, Linux, and macOS", "Universal security solution"),
        ("Real-time Detection", "Live process monitoring and analysis", "Immediate threat identification"),
        ("Encrypted Storage", "AES-256 encryption for sensitive data", "Military-grade data protection"),
        ("Risk Scoring", "Quantified threat assessment (0-100)", "Clear risk understanding"),
        ("Comprehensive Analysis", "Multiple detection methods combined", "Reduced false positives"),
        ("User-Friendly", "Rich terminal interface with colors", "Easy to use and understand"),
        ("Modular Design", "Separate modules for each tool", "Easy to extend and maintain"),
        ("Permission Handling", "Graceful fallback for limited access", "Works without admin rights")
    ]
    
    for feature, description, benefit in features:
        features_table.add_row(feature, description, benefit)
    
    console.print(features_table)


def main():
    """Run the demo."""
    try:
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Display banner
        demo_banner()
        
        # Run demos
        demo_keylogger_detection()
        demo_password_vault()
        demo_phishing_detection()
        demo_cross_platform()
        demo_security_features()
        
        # Final message
        final_text = Text()
        final_text.append("🎉 ", style="green")
        final_text.append("Demo completed successfully!\n\n", style="green")
        final_text.append("To use the actual Security Toolkit:\n", style="blue")
        final_text.append("1. Install dependencies: ", style="white")
        final_text.append("pip install -r requirements.txt\n", style="yellow")
        final_text.append("2. Run the toolkit: ", style="white")
        final_text.append("python security_toolkit.py\n", style="yellow")
        final_text.append("3. Test the installation: ", style="white")
        final_text.append("python test_toolkit.py", style="yellow")
        
        final_panel = Panel(final_text, title="Next Steps", border_style="green")
        console.print(final_panel)
        
    except Exception as e:
        console.print(f"[bold red]Demo error: {str(e)}[/bold red]")
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
