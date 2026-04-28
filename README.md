# 🔐 Password Security Toolkit

A full-stack cybersecurity web application built with Python Flask and HTML/JavaScript — live and accessible from any device worldwide.

## 🌐 Live Demo
👉 **[Try it live here](https://password-security-toolkit-9i75.onrender.com)**

## 🌟 Features

- **Password Strength Checker** — analyses passwords against 6 security criteria with real-time feedback and estimated crack time
- **Breach Detection** — checks against 12+ billion leaked passwords using HaveIBeenPwned API with k-Anonymity (your password is never sent over the internet)
- **Smart Password Generator** — OSINT-aware generator that takes your personal details and creates a password with zero connection to your identity
- **AES-256 Encrypted Vault** — stores passwords per platform (Gmail, TikTok, Instagram, WhatsApp etc.) encrypted with Fernet/PBKDF2 — plain text never touches disk
- **User Login System** — each user has a unique account with SHA-256 hashed credentials and login attempt limiting
- **4-Digit PIN Protection** — second layer of vault security, auto-locks when switching tabs
- **Rate Limiting** — brute force protection on login attempts

## 🛡️ Security Concepts Applied

- SHA-256 password hashing
- AES-256 encryption via Python Fernet
- PBKDF2 key derivation (200,000 rounds)
- k-Anonymity for private breach checking
- OSINT awareness in password generation
- Two-factor vault protection (master password + PIN)
- PostgreSQL database for secure user storage
- Rate limiting against brute force attacks

## 🚀 How to Run Locally

**1. Clone the repository**
```bash
git clone https://github.com/mulei-tech27/password-security-toolkit.git
cd password-security-toolkit
```

**2. Install dependencies**
```bash
pip install flask flask-cors requests cryptography psycopg2-binary flask-limiter
```

**3. Set up PostgreSQL and add your DATABASE_URL to a .env file**
```bash
DATABASE_URL=postgresql://username:password@localhost/passwordtoolkit
```

**4. Run the app**
```bash
python app.py
```

**5. Open in browser**
## 🗂️ Project Structure
password-security-toolkit/
├── app.py           # Flask backend — API endpoints, encryption, database
├── index.html       # Frontend — 3-tab UI (Checker, Smart Gen, Vault)
├── checker.py       # Original terminal-based password checker
├── requirements.txt # Python dependencies
├── Procfile         # Render deployment config
└── .gitignore       # Excludes sensitive files from version control
## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| Database | PostgreSQL |
| Encryption | AES-256 via Fernet, PBKDF2 |
| Security | SHA-256, k-Anonymity, Rate Limiting |
| Hosting | Render.com |
| Version Control | GitHub |

## 📚 What I Learned

Building this project taught me how real password managers work — from entropy and character pool mathematics to k-Anonymity, OSINT attack vectors, and production-grade encryption. Every security decision mirrors techniques used by tools like Bitwarden and 1Password.

## ⚠️ Disclaimer

This project is built for educational and portfolio purposes.

---
Built as a cybersecurity learning project 🛡️ | [Live Demo](https://password-security-toolkit-9i75.onrender.com) | [GitHub](https://github.com/mulei-tech27/password-security-toolkit)