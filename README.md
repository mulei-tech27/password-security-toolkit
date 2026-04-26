# 🔐 Password Security Toolkit

A full-stack cybersecurity web application built with Python Flask and HTML/JavaScript.

## 🌟 Features

- **Password Strength Checker** — analyses passwords against 6 security criteria with real-time feedback
- **Breach Detection** — checks passwords against 12+ billion leaked passwords using the HaveIBeenPwned API with k-Anonymity (your password is never sent over the internet)
- **Smart Password Generator** — OSINT-aware generator that takes your personal details and creates a password with zero connection to your identity
- **AES-256 Encrypted Vault** — stores passwords per platform (Gmail, TikTok, Instagram etc.) encrypted with Fernet/PBKDF2 — plain text never touches disk
- **User Login System** — each user has a unique account with SHA-256 hashed credentials
- **4-Digit PIN Protection** — second layer of security on the vault, auto-locks when switching tabs

## 🛡️ Security Concepts Applied

- SHA-256 password hashing
- AES-256 encryption via Python Fernet
- PBKDF2 key derivation (200,000 rounds)
- k-Anonymity for breach checking
- OSINT awareness in password generation
- Two-factor vault protection (master password + PIN)

## 🚀 How to Run

**1. Clone the repository**
```bash
git clone https://github.com/mulei-tech27/password-security-toolkit.git
cd password-security-toolkit
```

**2. Install dependencies**
```bash
pip install flask flask-cors requests cryptography
```

**3. Run the app**
```bash
python app.py
```

**4. Open in browser**
## 🗂️ Project Structure
## 🔧 Tech Stack

- **Backend** — Python 3.14, Flask, cryptography library
- **Frontend** — HTML5, CSS3, JavaScript (Fetch API)
- **Security** — SHA-256, AES-256-GCM, PBKDF2, HaveIBeenPwned API
- **Storage** — JSON file-based user store with encrypted vault entries

## 📚 What I Learned

Building this project taught me how real password managers work under the hood — from entropy and character pool mathematics to k-Anonymity, OSINT attack vectors, and production-grade encryption. Every security decision in this project mirrors techniques used by tools like Bitwarden and 1Password.

## ⚠️ Disclaimer

This project is built for educational and portfolio purposes. For production use, additional hardening would be recommended including rate limiting, HTTPS, and a proper database.

---
Built as a cybersecurity learning project 🛡️