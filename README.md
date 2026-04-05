# SafePass

Weak and guessed passwords are one of the most common ways people get hacked, and I wanted to build something that actually tackles that problem. Most password managers just generate a random string of characters that nobody can remember, so people end up writing it down or reusing the same password anyway — which defeats the point entirely.

SafePass takes a different approach. It generates passwords based on your answers to personal security questions, so the result is still strong but rooted in something you actually know. The goal was to find that balance between security and memorability.

I built this as my final year thesis project after graduating from my Cyber Security and Digital Forensics degree.

---

## How it works

You answer 5 personal questions — things like your favourite colour, your pet's name, the city you were born in. SafePass takes slices of each answer, combines them, enforces complexity rules (at least one uppercase, one number, one symbol) and then shuffles the result. You end up with a password that meets modern security standards but is still tied to answers only you would know.

Every password gets saved to a local database, encrypted with AES-256-GCM using a key derived from your login password. Nothing is stored in plaintext, nothing is sent anywhere — it all stays on your machine.

---

## Features

- Register and login with bcrypt-hashed passwords
- Generate passwords from personal security questions
- Password strength rating (Weak / Moderate / Strong / Very Strong)
- AES-256-GCM encrypted storage — passwords are encrypted before they ever touch the database
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
- View and decrypt saved passwords at any time
- Activity logging to `safepass.log`

---

## Running it

```bash
git clone https://github.com/basilfaisal75/Safepass.git
cd Safepass
pip3 install bcrypt cryptography
python3 login.py
```

1. Register an account
2. Login
3. Generate a password by answering the 5 questions
4. View your saved passwords anytime from the main menu

---

## Project structure

```
Safepass/
├── login.py               # Entry point - login, register, main menu
├── password_generator.py  # Password generation logic and UI
├── viewpassword.py        # View saved passwords
├── db_manager.py          # Database management
└── encryption_utils.py    # AES-GCM encryption and PBKDF2 key derivation
```

---

## Requirements

- Python 3.10+
- `bcrypt` — `pip3 install bcrypt`
- `cryptography` — `pip3 install cryptography`
- `tkinter` — included with Python
