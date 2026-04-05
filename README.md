# SafePass

A desktop password manager built in Python as a final-year Cyber Security (Forensics) thesis project. SafePass generates memorable, cryptographically strong passwords based on personal security questions, then stores them securely using AES-GCM encryption.

---

## Screenshots

> Login Screen
![Login](screenshots/login.png)

> Main Menu
![Main Menu](screenshots/menu.png)

> Password Generator
![Generator](screenshots/generator.png)

> Saved Passwords
![Passwords](screenshots/passwords.png)

---

## Features

- **User authentication** — Register and login with bcrypt-hashed passwords
- **Memorable password generation** — Passwords derived from answers to personal security questions, guaranteed to meet complexity requirements (uppercase, digit, symbol)
- **Password strength checker** — Rates generated passwords as Weak / Moderate / Strong / Very Strong
- **AES-GCM encrypted storage** — Saved passwords are encrypted at rest using a key derived from your login password via PBKDF2 (100,000 iterations, SHA-256)
- **Local SQLite database** — All data stays on your machine, nothing is sent externally
- **Activity logging** — All login attempts, registrations, and password operations are logged to `safepass.log`
- **Tkinter GUI** — Simple graphical interface accessible to non-technical users

---

## How It Works

### Password Generation
You answer 5 personal security questions. SafePass takes slices of each answer, combines them, then enforces complexity rules (uppercase, digit, punctuation) before shuffling the result. This makes passwords both memorable and secure.

### Encryption
When a password is saved:
1. A random 16-byte salt is generated
2. Your login password + salt are fed into PBKDF2-HMAC-SHA256 (100,000 iterations) to derive a 256-bit AES key
3. The password is encrypted with AES-GCM using a random 12-byte nonce
4. `salt + nonce + ciphertext` is Base64-encoded and stored in SQLite

When viewing passwords, the same process runs in reverse using your login password as the key.

---

## Project Structure

```
Safepass/
├── login.py               # Main entry point - login/register UI and main menu
├── password_generator.py  # Password generation logic and UI
├── viewpassword.py        # Saved password viewer UI
├── db_manager.py          # SQLite database manager (users + passwords tables)
├── encryption_utils.py    # AES-GCM encryption/decryption + PBKDF2 key derivation
└── safepass.log           # Activity log (auto-generated on first run)
```

---

## Installation

```bash
git clone https://github.com/basilfaisal75/Safepass.git
cd Safepass
pip3 install bcrypt cryptography
```

---

## Usage

```bash
python3 login.py
```

1. **Register** a new account with a username and password
2. **Login** with your credentials
3. From the main menu:
   - **Generate Password** - answer 5 questions to create and save a new password
   - **View Saved Passwords** - see all your stored passwords, decrypted in real time

---

## Security Design

| Component | Implementation |
|---|---|
| User password storage | bcrypt with random salt |
| Password encryption | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-HMAC-SHA256, 100,000 iterations |
| Nonce/salt generation | os.urandom() (cryptographically secure) |
| Data storage | Local SQLite - no network transmission |

---

## Requirements

- Python 3.10+
- `bcrypt` - `pip3 install bcrypt`
- `cryptography` - `pip3 install cryptography`
- `tkinter` - included with standard Python on Windows/Mac

---

## Disclaimer

This project was developed for academic purposes as part of a final-year thesis. It is intended to demonstrate applied skills in cryptography, secure software development, and cybersecurity principles.
