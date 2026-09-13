# SentinelCrypt

A cross-platform encryption suite with a desktop GUI and a web interface, built with Python and CustomTkinter.

## Features
- **AES-256-GCM Encryption**: Authenticated encryption for file integrity.
- **RSA-2048 Key Management**: Secure key pair generation and storage.
- **Modern GUI**: Built with CustomTkinter, dark mode.
- **PBKDF2 Key Derivation**: Protection against brute-force attacks.

## Tech Stack
- **Language**: Python 3.10+
- **Crypto**: `cryptography` library (Hazmat primitives)
- **GUI**: `CustomTkinter`

## Installation
1. Clone the repo
2. `pip install -r requirements.txt`
3. `python main.py`

## Security Disclaimer
This tool is for educational and portfolio purposes. While it uses industry-standard algorithms, always use established tools (like GPG or Veracrypt) for critical data protection.

## License
MIT
