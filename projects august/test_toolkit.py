#!/usr/bin/env python3
"""
Test Script for Security Toolkit

This script tests basic functionality of the security toolkit modules.
"""

import sys
import os

def test_imports():
    """Test that all modules can be imported."""
    print("Testing module imports...")
    
    try:
        from modules.keylogger_detector import KeyloggerDetector
        print("✅ KeyloggerDetector imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import KeyloggerDetector: {e}")
        return False
    
    try:
        from modules.password_vault import PasswordVault
        print("✅ PasswordVault imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PasswordVault: {e}")
        return False
    
    try:
        from modules.phishing_detector import PhishingDetector
        print("✅ PhishingDetector imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PhishingDetector: {e}")
        return False
    
    return True

def test_instantiations():
    """Test that all classes can be instantiated."""
    print("\nTesting class instantiations...")
    
    try:
        from modules.keylogger_detector import KeyloggerDetector
        detector = KeyloggerDetector()
        print("✅ KeyloggerDetector instantiated successfully")
    except Exception as e:
        print(f"❌ Failed to instantiate KeyloggerDetector: {e}")
        return False
    
    try:
        from modules.password_vault import PasswordVault
        vault = PasswordVault()
        print("✅ PasswordVault instantiated successfully")
    except Exception as e:
        print(f"❌ Failed to instantiate PasswordVault: {e}")
        return False
    
    try:
        from modules.phishing_detector import PhishingDetector
        phish_detector = PhishingDetector()
        print("✅ PhishingDetector instantiated successfully")
    except Exception as e:
        print(f"❌ Failed to instantiate PhishingDetector: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of each module."""
    print("\nTesting basic functionality...")
    
    try:
        from modules.keylogger_detector import KeyloggerDetector
        detector = KeyloggerDetector()
        platform = detector.detect_platform()
        print(f"✅ KeyloggerDetector platform detection: {platform}")
    except Exception as e:
        print(f"❌ KeyloggerDetector functionality test failed: {e}")
        return False
    
    try:
        from modules.phishing_detector import PhishingDetector
        detector = PhishingDetector()
        # Test with a simple URL
        test_url = "https://example.com"
        analysis = detector.analyze_url(test_url)
        print(f"✅ PhishingDetector basic analysis: Risk score {analysis['risk_score']}")
    except Exception as e:
        print(f"❌ PhishingDetector functionality test failed: {e}")
        return False
    
    return True

def main():
    """Run all tests."""
    print("🔒 Security Toolkit - Module Test")
    print("=" * 40)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Check module dependencies.")
        return False
    
    # Test instantiations
    if not test_instantiations():
        print("\n❌ Instantiation tests failed. Check class constructors.")
        return False
    
    # Test basic functionality
    if not test_basic_functionality():
        print("\n❌ Functionality tests failed. Check module implementation.")
        return False
    
    print("\n🎉 All tests passed! The Security Toolkit is ready to use.")
    print("\nTo run the toolkit:")
    print("  python security_toolkit.py")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
