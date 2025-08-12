# Security Toolkit - Quick Start Guide

Get up and running with the Security Toolkit in minutes!

## 🚀 Quick Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Test the Installation
```bash
python test_toolkit.py
```

### 3. Run the Toolkit
```bash
python security_toolkit.py
```

## 🎯 What You Get

The Security Toolkit provides three powerful security tools in one application:

### 🔍 Keylogger Detection
- **What it does**: Scans your system for suspicious processes that might be keyloggers
- **Best results**: Run as Administrator (Windows) or with sudo (Linux)
- **Output**: List of suspicious processes with risk scores and reasons

### 🔐 Password Vault
- **What it does**: Securely stores your passwords using military-grade encryption
- **Security**: Your master password encrypts everything
- **Features**: Add, view, edit, delete, and search credentials

### 🌐 Phishing Detection
- **What it does**: Analyzes URLs for signs of phishing attempts
- **Detection**: IP addresses, typosquatting, suspicious keywords, redirects
- **Output**: Risk score (0-100) with detailed analysis

## 📱 Using the Toolkit

### Main Menu
1. **Run Keylogger Scan** - Detect suspicious processes
2. **Open Password Vault** - Manage your passwords
3. **Check Phishing URL** - Analyze suspicious links
4. **System Information** - View security details
5. **Exit** - Close the application

### Keylogger Scan
- Automatically detects your platform (Windows/Linux/macOS)
- Scans all running processes
- Provides suspicion scores and reasons
- Option to save results to file

### Password Vault
- **First time**: Set a master password (minimum 8 characters)
- **Subsequent uses**: Enter master password to unlock
- **Operations**: Full CRUD operations for credentials
- **Security**: All data encrypted with your master password

### Phishing Detection
- Enter any URL (with or without http/https)
- Get comprehensive risk analysis
- View detailed findings and recommendations
- Option to save analysis results

## 🔧 Platform-Specific Notes

### Windows
- Run as Administrator for best keylogger detection
- Some antivirus software may flag the toolkit (add to exclusions if needed)

### Linux
- Run with `sudo` for complete process access
- May need to install additional packages: `sudo apt-get install python3-dev`

### macOS
- Some features limited due to security restrictions
- Grant necessary permissions in System Preferences > Security & Privacy

## 🚨 Troubleshooting

### Common Issues

**Import Error**: Make sure you're in the correct directory and all modules are present
```bash
ls modules/
# Should show: __init__.py, keylogger_detector.py, password_vault.py, phishing_detector.py
```

**Permission Denied**: Run with appropriate privileges
- Windows: Right-click → Run as Administrator
- Linux: `sudo python3 security_toolkit.py`
- macOS: Grant permissions in System Preferences

**Module Not Found**: Install dependencies
```bash
pip install -r requirements.txt
```

**Vault Access Issues**: Delete vault files to start fresh
```bash
rm vault.enc vault.salt  # Linux/macOS
del vault.enc vault.salt  # Windows
```

## 📊 Example Outputs

### Keylogger Scan Results
```
⚠️  Found 2 suspicious processes:

┌─────┬─────────────────┬──────────────────┬─────────────────┬─────────────────┐
│ PID │ Process Name    │ Suspicion Score  │ Reasons         │ Executable      │
├─────┼─────────────────┼──────────────────┼─────────────────┼─────────────────┤
│ 1234│ suspicious.exe  │ 75/100           │ Known suspicious│ C:\temp\susp   │
│     │                 │                  │ process name    │                 │
└─────┴─────────────────┴──────────────────┴─────────────────┴─────────────────┘
```

### Phishing Analysis
```
🔍 Analyzing URL: http://fake-paypal.com/login

Analysis Results
┌─────────────────────────────────────────────────────────────┐
│ URL: http://fake-paypal.com/login                          │
│ Risk Score: 85/100                                         │
│ Risk Level: CRITICAL                                       │
│ Protocol: http                                             │
│ Domain: fake-paypal.com                                    │
└─────────────────────────────────────────────────────────────┘

⚠️  Issues Found (3):
┌─────────────────────────────────────────────────┬──────────────┐
│ Issue                                          │ Risk Impact  │
├─────────────────────────────────────────────────┼──────────────┤
│ Uses HTTP instead of HTTPS (insecure)          │ Medium       │
│ Possible typosquatting of paypal               │ High         │
│ Suspicious keywords found: login               │ Low          │
└─────────────────────────────────────────────────┴──────────────┘
```

## 🔒 Security Best Practices

1. **Run scans regularly** - Check for keyloggers weekly
2. **Use strong master password** - 12+ characters, mix of types
3. **Verify URLs** - Always check suspicious links before clicking
4. **Keep updated** - Update the toolkit and dependencies regularly
5. **Backup vault** - Keep a secure backup of your password vault

## 📞 Getting Help

If you encounter issues:

1. Check this Quick Start Guide
2. Review the full README.md
3. Run the test script: `python test_toolkit.py`
4. Check Python version: `python --version` (3.8+ required)

## 🎉 You're Ready!

The Security Toolkit is now ready to protect your system. Remember:
- **Scan regularly** for keyloggers
- **Store passwords** securely in the vault
- **Verify URLs** before entering credentials
- **Stay vigilant** - security is an ongoing process

Happy securing! 🔒✨
