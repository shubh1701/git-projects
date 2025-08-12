"""
Security Toolkit Modules Package

This package contains the three main security tools:
- Keylogger Detection Tool
- Password Vault with Encryption
- Phishing Website Detector
"""

__version__ = "1.0.0"
__author__ = "Security Toolkit Team"

from .keylogger_detector import KeyloggerDetector
from .password_vault import PasswordVault
from .phishing_detector import PhishingDetector

__all__ = ['KeyloggerDetector', 'PasswordVault', 'PhishingDetector']
