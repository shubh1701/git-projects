"""
Phishing Website Detector

Analyzes URLs for suspicious features that indicate potential phishing attempts.
Features: IP address detection, subdomain analysis, keyword scanning, and risk scoring.
"""

import re
import socket
import dns.resolver
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
import time

console = Console()


class PhishingDetector:
    """Comprehensive phishing website detection tool."""
    
    def __init__(self):
        # Common phishing keywords that raise suspicion
        self.phishing_keywords = [
            'login', 'signin', 'sign-in', 'sign_in', 'log-in', 'log_in',
            'secure', 'security', 'verify', 'verification', 'confirm',
            'update', 'upgrade', 'account', 'banking', 'paypal', 'ebay',
            'amazon', 'google', 'facebook', 'twitter', 'instagram',
            'password', 'username', 'credential', 'authentication',
            'suspension', 'suspended', 'locked', 'unlock', 'restore',
            'recovery', 'reset', 'change', 'modify', 'edit', 'billing',
            'payment', 'credit', 'debit', 'card', 'bank', 'financial'
        ]
        
        # Known legitimate domains (whitelist)
        self.legitimate_domains = {
            'google.com', 'gmail.com', 'youtube.com', 'facebook.com',
            'amazon.com', 'paypal.com', 'ebay.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'spotify.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com'
        }
        
        # Common typosquatting patterns
        self.typosquatting_patterns = [
            (r'g00gle', 'google'),
            (r'g0ogle', 'google'),
            (r'go0gle', 'google'),
            (r'gogle', 'google'),
            (r'gooogle', 'google'),
            (r'facebo0k', 'facebook'),
            (r'faceb00k', 'facebook'),
            (r'facebok', 'facebook'),
            (r'amaz0n', 'amazon'),
            (r'amaz0n', 'amazon'),
            (r'paypa1', 'paypal'),
            (r'paypa1', 'paypal'),
            (r'ebay', 'ebay'),
            (r'ebay', 'ebay'),
            (r'micros0ft', 'microsoft'),
            (r'micros0ft', 'microsoft'),
            (r'app1e', 'apple'),
            (r'app1e', 'apple'),
            (r'netf1ix', 'netflix'),
            (r'netf1ix', 'netflix'),
            (r'spot1fy', 'spotify'),
            (r'spot1fy', 'spotify'),
            (r'tw1tter', 'twitter'),
            (r'tw1tter', 'twitter'),
            (r'instagr4m', 'instagram'),
            (r'instagr4m', 'instagram'),
            (r'1inkedin', 'linkedin'),
            (r'1inkedin', 'linkedin'),
            (r'g1thub', 'github'),
            (r'g1thub', 'github'),
            (r'stack0verflow', 'stackoverflow'),
            (r'stack0verflow', 'stackoverflow')
        ]
    
    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL for phishing indicators."""
        console.print(f"\n[bold blue]🔍 Analyzing URL: {url}[/bold blue]")
        
        # Initialize results
        analysis = {
            'url': url,
            'risk_score': 0,
            'issues': [],
            'warnings': [],
            'details': {}
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            
            # Basic URL validation
            if not parsed_url.scheme or not parsed_url.netloc:
                analysis['issues'].append("Invalid URL format")
                analysis['risk_score'] += 50
                return analysis
            
            # Check protocol (HTTP vs HTTPS)
            protocol_score, protocol_issues = self._check_protocol(parsed_url)
            analysis['risk_score'] += protocol_score
            analysis['issues'].extend(protocol_issues)
            
            # Check domain structure
            domain_score, domain_issues = self._check_domain_structure(parsed_url.netloc)
            analysis['risk_score'] += domain_score
            analysis['issues'].extend(domain_issues)
            
            # Check for IP addresses
            ip_score, ip_issues = self._check_ip_address(parsed_url.netloc)
            analysis['risk_score'] += ip_score
            analysis['issues'].extend(ip_issues)
            
            # Check for typosquatting
            typosquat_score, typosquat_issues = self._check_typosquatting(parsed_url.netloc)
            analysis['risk_score'] += typosquat_score
            analysis['issues'].extend(typosquat_issues)
            
            # Check for suspicious keywords
            keyword_score, keyword_issues = self._check_suspicious_keywords(url)
            analysis['risk_score'] += keyword_score
            analysis['issues'].extend(keyword_issues)
            
            # Check domain age and reputation (if possible)
            reputation_score, reputation_issues = self._check_domain_reputation(parsed_url.netloc)
            analysis['risk_score'] += reputation_score
            analysis['issues'].extend(reputation_issues)
            
            # Check for redirects
            redirect_score, redirect_issues = self._check_redirects(url)
            analysis['risk_score'] += redirect_score
            analysis['issues'].extend(redirect_issues)
            
            # Cap risk score at 100
            analysis['risk_score'] = min(analysis['risk_score'], 100)
            
            # Determine risk level
            analysis['risk_level'] = self._get_risk_level(analysis['risk_score'])
            
            # Add analysis details
            analysis['details'] = {
                'protocol': parsed_url.scheme,
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'fragment': parsed_url.fragment
            }
            
        except Exception as e:
            analysis['issues'].append(f"Error during analysis: {str(e)}")
            analysis['risk_score'] += 30
        
        return analysis
    
    def _check_protocol(self, parsed_url) -> Tuple[int, List[str]]:
        """Check if the URL uses secure protocol."""
        score = 0
        issues = []
        
        if parsed_url.scheme == 'http':
            score += 25
            issues.append("Uses HTTP instead of HTTPS (insecure)")
        elif parsed_url.scheme == 'https':
            score -= 10  # Bonus for using HTTPS
            issues.append("Uses HTTPS (secure)")
        else:
            score += 15
            issues.append(f"Uses non-standard protocol: {parsed_url.scheme}")
        
        return score, issues
    
    def _check_domain_structure(self, domain: str) -> Tuple[int, List[str]]:
        """Check domain structure for suspicious patterns."""
        score = 0
        issues = []
        
        # Count subdomains
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            score += 20
            issues.append(f"Excessive subdomains: {len(subdomains)} levels")
        
        # Check for very long domain names
        if len(domain) > 50:
            score += 15
            issues.append("Unusually long domain name")
        
        # Check for suspicious subdomain patterns
        suspicious_subdomains = ['secure', 'login', 'signin', 'verify', 'update']
        for subdomain in subdomains[:-2]:  # Exclude TLD and main domain
            if subdomain.lower() in suspicious_subdomains:
                score += 15
                issues.append(f"Suspicious subdomain: {subdomain}")
        
        return score, issues
    
    def _check_ip_address(self, domain: str) -> Tuple[int, List[str]]:
        """Check if domain is an IP address instead of a domain name."""
        score = 0
        issues = []
        
        # Check if it's an IP address
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, domain):
            score += 40
            issues.append("Domain is an IP address instead of a domain name")
            
            # Check if it's a private IP
            try:
                ip_parts = domain.split('.')
                if (ip_parts[0] == '10' or 
                    (ip_parts[0] == '192' and ip_parts[1] == '168') or
                    (ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31)):
                    score += 20
                    issues.append("IP address is in private range")
            except (ValueError, IndexError):
                pass
        
        return score, issues
    
    def _check_typosquatting(self, domain: str) -> Tuple[int, List[str]]:
        """Check for typosquatting attempts."""
        score = 0
        issues = []
        
        # Extract main domain (remove subdomains)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            main_domain = '.'.join(domain_parts[-2:])
            
            # Check against known typosquatting patterns
            for pattern, legitimate in self.typosquatting_patterns:
                if re.search(pattern, main_domain, re.IGNORECASE):
                    score += 35
                    issues.append(f"Possible typosquatting of {legitimate}")
                    break
            
            # Check for character substitutions
            for legitimate in self.legitimate_domains:
                if self._calculate_similarity(main_domain, legitimate) > 0.8:
                    if main_domain != legitimate:
                        score += 30
                        issues.append(f"Similar to legitimate domain: {legitimate}")
                        break
        
        return score, issues
    
    def _check_suspicious_keywords(self, url: str) -> Tuple[int, List[str]]:
        """Check for suspicious keywords in the URL."""
        score = 0
        issues = []
        
        url_lower = url.lower()
        
        # Count suspicious keywords
        found_keywords = []
        for keyword in self.phishing_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            score += min(len(found_keywords) * 10, 30)  # Max 30 points for keywords
            issues.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
        # Check for excessive use of keywords
        if len(found_keywords) > 3:
            score += 15
            issues.append("Excessive use of suspicious keywords")
        
        return score, issues
    
    def _check_domain_reputation(self, domain: str) -> Tuple[int, List[str]]:
        """Check domain reputation and age."""
        score = 0
        issues = []
        
        try:
            # Try to resolve the domain
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Checking domain reputation...", total=1)
                
                # Check if domain resolves
                try:
                    ip = socket.gethostbyname(domain)
                    progress.advance(task)
                except socket.gaierror:
                    score += 25
                    issues.append("Domain does not resolve")
                    progress.advance(task)
                    return score, issues
                
                # Check for suspicious TLDs
                suspicious_tlds = ['.xyz', '.top', '.club', '.site', '.online', '.tech']
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        score += 15
                        issues.append(f"Suspicious TLD: {tld}")
                        break
                
        except Exception as e:
            issues.append(f"Could not check domain reputation: {str(e)}")
        
        return score, issues
    
    def _check_redirects(self, url: str) -> Tuple[int, List[str]]:
        """Check for suspicious redirects."""
        score = 0
        issues = []
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Checking for redirects...", total=1)
                
                # Check for redirects (with timeout)
                try:
                    response = requests.head(url, allow_redirects=True, timeout=10)
                    if response.history:
                        score += 20
                        issues.append(f"URL redirects {len(response.history)} times")
                        
                        # Check final destination
                        final_url = response.url
                        if final_url != url:
                            issues.append(f"Final destination: {final_url}")
                            
                            # Analyze final destination
                            final_analysis = self.analyze_url(final_url)
                            if final_analysis['risk_score'] > score:
                                score += 15
                                issues.append("Final destination has higher risk score")
                    
                    progress.advance(task)
                    
                except requests.exceptions.RequestException as e:
                    issues.append(f"Could not check redirects: {str(e)}")
                    progress.advance(task)
                    
        except Exception as e:
            issues.append(f"Error checking redirects: {str(e)}")
        
        return score, issues
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance."""
        if str1 == str2:
            return 1.0
        
        len1, len2 = len(str1), len(str2)
        if len1 == 0:
            return 0.0
        if len2 == 0:
            return 0.0
        
        # Simple similarity calculation
        max_len = max(len1, len2)
        min_len = min(len1, len2)
        
        # Count common characters
        common = 0
        for char in str1:
            if char in str2:
                common += 1
        
        return common / max_len
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "SAFE"
    
    def display_analysis_results(self, analysis: Dict):
        """Display analysis results in a formatted way."""
        # Risk level with color coding
        risk_colors = {
            'SAFE': 'green',
            'LOW': 'yellow',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'red'
        }
        
        risk_color = risk_colors.get(analysis['risk_level'], 'white')
        
        # Main results panel
        results_text = Text()
        results_text.append(f"URL: {analysis['url']}\n", style="blue")
        results_text.append(f"Risk Score: {analysis['risk_score']}/100\n", style=risk_color)
        results_text.append(f"Risk Level: {analysis['risk_level']}\n", style=risk_color)
        
        if analysis['details']:
            results_text.append(f"Protocol: {analysis['details']['protocol']}\n", style="cyan")
            results_text.append(f"Domain: {analysis['details']['domain']}\n", style="cyan")
            if analysis['details']['path']:
                results_text.append(f"Path: {analysis['details']['path']}\n", style="cyan")
        
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
                elif 'keyword' in issue or 'subdomain' in issue:
                    impact = "Low"
                else:
                    impact = "Medium"
                
                issues_table.add_row(issue, impact)
            
            console.print(issues_table)
        
        # Recommendations
        recommendations = self._generate_recommendations(analysis)
        if recommendations:
            console.print(f"\n[bold blue]💡 Recommendations:[/bold blue]")
            for rec in recommendations:
                console.print(f"• {rec}")
        
        # Summary
        summary_text = Text()
        if analysis['risk_score'] >= 60:
            summary_text.append("This URL shows significant signs of being a phishing attempt. ", style="red")
            summary_text.append("Avoid entering any personal information.", style="red")
        elif analysis['risk_score'] >= 40:
            summary_text.append("This URL has some suspicious characteristics. ", style="yellow")
            summary_text.append("Exercise caution and verify the source.", style="yellow")
        elif analysis['risk_score'] >= 20:
            summary_text.append("This URL has minor suspicious elements. ", style="orange")
            summary_text.append("Proceed with caution.", style="orange")
        else:
            summary_text.append("This URL appears to be safe. ", style="green")
            summary_text.append("No significant threats detected.", style="green")
        
        summary_panel = Panel(summary_text, title="Summary", border_style=risk_color)
        console.print(summary_panel)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        if analysis['risk_score'] >= 80:
            recommendations.extend([
                "Do not visit this URL under any circumstances",
                "Report this URL to your security team",
                "Check if your system has been compromised"
            ])
        elif analysis['risk_score'] >= 60:
            recommendations.extend([
                "Avoid entering any personal information",
                "Verify the URL with the legitimate source",
                "Use a different method to access the service"
            ])
        elif analysis['risk_score'] >= 40:
            recommendations.extend([
                "Verify the URL is legitimate before proceeding",
                "Check for HTTPS and valid SSL certificates",
                "Look for typos or suspicious characters in the domain"
            ])
        elif analysis['risk_score'] >= 20:
            recommendations.extend([
                "Double-check the URL spelling",
                "Ensure you're on the correct website",
                "Look for security indicators in your browser"
            ])
        else:
            recommendations.append("No specific recommendations needed - URL appears safe")
        
        return recommendations
    
    def run_interactive_mode(self):
        """Run the phishing detector in interactive mode."""
        console.print("\n[bold blue]🌐 Phishing Website Detector[/bold blue]")
        console.print("Enter URLs to analyze for phishing indicators.\n")
        
        while True:
            url = Prompt.ask("Enter URL to analyze (or 'quit' to exit)")
            
            if url.lower() in ['quit', 'exit', 'q']:
                console.print("[green]Exiting phishing detector...[/green]")
                break
            
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            try:
                # Analyze the URL
                analysis = self.analyze_url(url)
                
                # Display results
                self.display_analysis_results(analysis)
                
            except Exception as e:
                console.print(f"[red]Error analyzing URL: {str(e)}[/red]")
            
            console.print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    # Test the detector
    detector = PhishingDetector()
    detector.run_interactive_mode()
