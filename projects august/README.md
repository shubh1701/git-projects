# Security Toolkit

A comprehensive cross-platform security toolkit that bundles three essential security tools into one application with a clean, menu-based interface.

## Features

### 1. Keylogger Detection Tool
- **Cross-platform process monitoring** using `psutil`
- **Windows**: Detects suspicious processes, modules, and network connections
- **Linux**: Checks `/proc` for `/dev/input` access and suspicious processes
- **macOS**: Monitors running processes and network activity (within permission limits)
- **Output**: PID, process name, suspicion reasons, and related file/network handles

### 2. Password Vault with Encryption
- **Military-grade encryption** using the `cryptography` library (Fernet)
- **Secure storage** in encrypted files
- **Features**: Add, retrieve, and delete credentials
- **Master password protection** required for access

### 3. Phishing Website Detector
- **URL analysis** for suspicious features
- **Detection methods**:
  - IP addresses instead of domains
  - Excessive subdomains
  - Common phishing keywords
  - HTTP vs HTTPS usage
  - Typosquatted domains
- **Risk scoring** with detailed issue reporting

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
1. **Clone or download** this repository
2. **Navigate** to the project directory
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Platform-Specific Notes
- **Windows**: Run as Administrator for full keylogger detection capabilities
- **Linux**: Run with `sudo` for complete process access
- **macOS**: Some features may be limited due to security restrictions

## Usage

### Running the Toolkit
```bash
python security_toolkit.py
```

### Menu Options
1. **Run Keylogger Scan** - Scan for suspicious processes
2. **Open Password Vault** - Manage encrypted credentials
3. **Check Phishing URL** - Analyze URLs for phishing indicators
4. **Exit** - Close the application

### Keylogger Detection
- Automatically detects platform and runs appropriate checks
- Provides detailed process information and suspicion indicators
- Handles permission errors gracefully

### Password Vault
- **First time**: Set a master password
- **Subsequent uses**: Enter master password to unlock
- **Operations**: Add, view, delete, and search credentials
- **Security**: All data encrypted with your master password

### Phishing Detection
- Enter any URL for analysis
- Receive risk score (0-100) and detailed findings
- Color-coded output for easy interpretation

## Security Features

- **Encryption**: AES-256 encryption for password storage
- **Permission handling**: Graceful fallback when admin access unavailable
- **Cross-platform**: Consistent behavior across Windows, Linux, and macOS
- **Modular design**: Easy to extend with additional security tools

## File Structure

```
security_toolkit/
├── security_toolkit.py      # Main application entry point
├── modules/
│   ├── __init__.py
│   ├── keylogger_detector.py
│   ├── password_vault.py
│   └── phishing_detector.py
├── requirements.txt          # Python dependencies
├── README.md               # This file
└── .gitignore             # Git ignore file
```

## Dependencies

- **cryptography**: Encryption and decryption operations
- **psutil**: Cross-platform process and system utilities
- **requests**: HTTP requests for URL analysis
- **rich**: Beautiful terminal output with colors
- **colorama**: Cross-platform colored terminal text
- **dnspython**: DNS resolution and domain analysis
- **urllib3**: HTTP client library

## Contributing

This toolkit is designed with modularity in mind. To add new security tools:

1. Create a new module in the `modules/` directory
2. Implement the required interface
3. Add the tool to the main menu in `security_toolkit.py`
4. Update this README with new feature information

## Disclaimer

This toolkit is for educational and security testing purposes. Always ensure you have proper authorization before scanning systems or networks. The authors are not responsible for any misuse of this software.

## License

This project is open source and available under the MIT License.
