"""
Keylogger Detection Tool

Cross-platform tool to detect suspicious processes that might be keyloggers.
Supports Windows, Linux, and macOS with platform-specific detection methods.
"""

import os
import sys
import platform
import psutil
import time
from typing import List, Dict, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class KeyloggerDetector:
    """Cross-platform keylogger detection tool."""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.suspicious_processes = []
        self.suspicious_keywords = [
            'keylog', 'logger', 'spy', 'monitor', 'track', 'capture',
            'hook', 'inject', 'stealer', 'grabber', 'recorder'
        ]
        
        # Platform-specific suspicious process names
        self.platform_suspicious = {
            'windows': [
                'ahk.exe', 'autohotkey.exe', 'keylogger.exe', 'spy.exe',
                'monitor.exe', 'hook.exe', 'inject.exe', 'stealer.exe'
            ],
            'linux': [
                'keylogger', 'spy', 'monitor', 'hook', 'inject',
                'stealer', 'grabber', 'recorder'
            ],
            'darwin': [  # macOS
                'keylogger', 'spy', 'monitor', 'hook', 'inject',
                'stealer', 'grabber', 'recorder'
            ]
        }
    
    def detect_platform(self) -> str:
        """Detect the current operating system."""
        return self.platform
    
    def scan_processes(self) -> List[Dict]:
        """Scan all running processes for suspicious activity."""
        console.print("\n[bold blue]🔍 Starting Keylogger Detection Scan...[/bold blue]")
        
        suspicious_found = []
        
        try:
            # Get all running processes
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning processes...", total=len(processes))
                
                for proc in processes:
                    try:
                        suspicion_score = 0
                        reasons = []
                        
                        # Check process name for suspicious keywords
                        if proc.info['name']:
                            proc_name_lower = proc.info['name'].lower()
                            
                            # Check against platform-specific suspicious names
                            if proc_name_lower in self.platform_suspicious.get(self.platform, []):
                                suspicion_score += 50
                                reasons.append("Known suspicious process name")
                            
                            # Check for suspicious keywords in name
                            for keyword in self.suspicious_keywords:
                                if keyword in proc_name_lower:
                                    suspicion_score += 30
                                    reasons.append(f"Contains suspicious keyword: {keyword}")
                        
                        # Platform-specific checks
                        if self.platform == 'windows':
                            score, platform_reasons = self._check_windows_process(proc)
                            suspicion_score += score
                            reasons.extend(platform_reasons)
                        elif self.platform == 'linux':
                            score, platform_reasons = self._check_linux_process(proc)
                            suspicion_score += score
                            reasons.extend(platform_reasons)
                        elif self.platform == 'darwin':
                            score, platform_reasons = self._check_macos_process(proc)
                            suspicion_score += score
                            reasons.extend(platform_reasons)
                        
                        # Check for high CPU usage (potential monitoring)
                        try:
                            cpu_percent = proc.cpu_percent(interval=0.1)
                            if cpu_percent > 50:
                                suspicion_score += 20
                                reasons.append(f"High CPU usage: {cpu_percent:.1f}%")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        
                        # Check for suspicious command line arguments
                        if proc.info['cmdline']:
                            cmdline = ' '.join(proc.info['cmdline']).lower()
                            for keyword in self.suspicious_keywords:
                                if keyword in cmdline:
                                    suspicion_score += 25
                                    reasons.append(f"Suspicious command line argument: {keyword}")
                        
                        # If suspicion score is high enough, add to list
                        if suspicion_score >= 30:
                            suspicious_found.append({
                                'pid': proc.pid,
                                'name': proc.info['name'] or 'Unknown',
                                'exe': proc.info['exe'] or 'Unknown',
                                'cmdline': proc.info['cmdline'] or [],
                                'suspicion_score': suspicion_score,
                                'reasons': reasons
                            })
                        
                        progress.advance(task)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        progress.advance(task)
                        continue
            
            return suspicious_found
            
        except Exception as e:
            console.print(f"[bold red]Error during process scan: {str(e)}[/bold red]")
            return []
    
    def _check_windows_process(self, proc) -> Tuple[int, List[str]]:
        """Windows-specific process checks."""
        score = 0
        reasons = []
        
        try:
            # Check for suspicious DLLs
            try:
                dlls = proc.memory_maps()
                for dll in dlls:
                    dll_lower = dll.path.lower()
                    if any(keyword in dll_lower for keyword in self.suspicious_keywords):
                        score += 20
                        reasons.append(f"Suspicious DLL loaded: {os.path.basename(dll.path)}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Check for suspicious network connections
            try:
                connections = proc.connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        # Check for suspicious remote addresses
                        if conn.raddr and conn.raddr.ip:
                            if conn.raddr.ip.startswith('192.168.') or conn.raddr.ip.startswith('10.'):
                                score += 15
                                reasons.append(f"Network connection to private IP: {conn.raddr.ip}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except Exception:
            pass
        
        return score, reasons
    
    def _check_linux_process(self, proc) -> Tuple[int, List[str]]:
        """Linux-specific process checks."""
        score = 0
        reasons = []
        
        try:
            # Check if process has access to input devices
            try:
                proc_path = f"/proc/{proc.pid}"
                fd_path = f"{proc_path}/fd"
                
                if os.path.exists(fd_path):
                    for fd in os.listdir(fd_path):
                        try:
                            fd_link = os.readlink(f"{fd_path}/{fd}")
                            if '/dev/input' in fd_link or '/dev/event' in fd_link:
                                score += 40
                                reasons.append(f"Access to input device: {fd_link}")
                        except (OSError, FileNotFoundError):
                            continue
            except (OSError, FileNotFoundError):
                pass
            
            # Check for suspicious file descriptors
            try:
                open_files = proc.open_files()
                for file in open_files:
                    if '/dev/input' in file.path or '/dev/event' in file.path:
                        score += 35
                        reasons.append(f"Input device file open: {file.path}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except Exception:
            pass
        
        return score, reasons
    
    def _check_macos_process(self, proc) -> Tuple[int, List[str]]:
        """macOS-specific process checks."""
        score = 0
        reasons = []
        
        try:
            # Check for accessibility permissions (common for keyloggers)
            try:
                # This is a simplified check - real implementation would need
                # to check TCC (Transparency, Consent, and Control) database
                # which requires special permissions
                pass
            except Exception:
                pass
            
            # Check for suspicious network activity
            try:
                connections = proc.connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        if conn.raddr and conn.raddr.ip:
                            # Check for suspicious patterns
                            if conn.raddr.ip.startswith('127.') or conn.raddr.ip.startswith('192.168.'):
                                score += 15
                                reasons.append(f"Local network connection: {conn.raddr.ip}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
        except Exception:
            pass
        
        return score, reasons
    
    def display_results(self, suspicious_processes: List[Dict]):
        """Display scan results in a formatted table."""
        if not suspicious_processes:
            console.print("\n[bold green]✅ No suspicious processes detected![/bold green]")
            return
        
        console.print(f"\n[bold red]⚠️  Found {len(suspicious_processes)} suspicious processes:[/bold red]")
        
        # Sort by suspicion score (highest first)
        suspicious_processes.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        # Create results table
        table = Table(title="Keylogger Detection Results")
        table.add_column("PID", style="cyan", no_wrap=True)
        table.add_column("Process Name", style="magenta")
        table.add_column("Suspicion Score", style="red")
        table.add_column("Reasons", style="yellow")
        table.add_column("Executable", style="blue")
        
        for proc in suspicious_processes:
            reasons_text = "\n".join(proc['reasons'])
            table.add_row(
                str(proc['pid']),
                proc['name'],
                f"{proc['suspicion_score']}/100",
                reasons_text,
                proc['exe'] if proc['exe'] != 'Unknown' else 'N/A'
            )
        
        console.print(table)
        
        # Summary panel
        total_score = sum(proc['suspicion_score'] for proc in suspicious_processes)
        avg_score = total_score / len(suspicious_processes)
        
        summary_text = Text()
        summary_text.append(f"Total Processes Scanned: {len(suspicious_processes)}\n", style="blue")
        summary_text.append(f"Average Suspicion Score: {avg_score:.1f}/100\n", style="yellow")
        summary_text.append(f"Highest Risk Process: {suspicious_processes[0]['name']} (PID: {suspicious_processes[0]['pid']})", style="red")
        
        summary_panel = Panel(summary_text, title="Scan Summary", border_style="blue")
        console.print(summary_panel)
    
    def run_scan(self) -> List[Dict]:
        """Run the complete keylogger detection scan."""
        try:
            # Display platform information
            platform_info = Panel(
                f"Platform: {platform.system()} {platform.release()}\n"
                f"Architecture: {platform.machine()}\n"
                f"Python: {sys.version.split()[0]}",
                title="System Information",
                border_style="green"
            )
            console.print(platform_info)
            
            # Run the scan
            suspicious_processes = self.scan_processes()
            
            # Display results
            self.display_results(suspicious_processes)
            
            return suspicious_processes
            
        except Exception as e:
            console.print(f"[bold red]Error during keylogger detection: {str(e)}[/bold red]")
            return []


if __name__ == "__main__":
    # Test the detector
    detector = KeyloggerDetector()
    detector.run_scan()
