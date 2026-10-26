# software-security-password-storage
Architecture to safely store passwords in python

`auth.py` implements password-based authentication that follows
**NIST SP 800-63B-4 §3.1.1.2 (Password Verifiers)** and the
**OWASP Password Storage Cheat Sheet**, using established libraries instead of custom crypto.

## Requirements

- Python 3.10 or newer
- Internet access (new passwords are checked against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) API)

## Setup

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create a secret pepper and store it in a `.env` file in the project folder:

   ```bash
   echo "PASSWORD_PEPPER=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
   ```

   `.env` is listed in `.gitignore` and must never be committed.
   If you set `PASSWORD_PEPPER` as an environment variable, it overrides the value in `.env`.
   Keep the pepper the same for as long as the stored hashes exist, because changing it
   invalidates every stored password.

## Run the demo

```bash
python auth.py
```

The demo checks a few sample passwords and prints whether each one is accepted or rejected, and why.
It then registers a user and tries three logins: a wrong password, the correct password, and the
correct password typed with full-width Unicode characters, which passes after normalisation.
Finally it prints the stored Argon2id hash.

Example output (shortened):

```text
'password'                       -> (False, 'Password must be at least 15 characters.')
'correcthorsebatterystaple'      -> (False, 'This password appeared in a data breach. Choose a different one.')
'edgar-htwg-demo-123'            -> (False, 'Password must not contain your username or the name of this service.')
'kiwi mango rocket violin 42'    -> (True, 'Strength 4/4')
login wrong: (False, 'Invalid username or password.')
login right: (True, 'Login ok.')
stored:      $argon2id$v=19$m=65536,t=3,p=4$...
```

## Use it in your own code

```python
import auth

auth.register("alice", "kiwi mango rocket violin 42")      # -> (True, "Strength 4/4")
auth.login("alice", "kiwi mango rocket violin 42")         # -> (True, "Login ok.")
auth.change_password("alice", "kiwi mango rocket violin 42", "new long passphrase here 7")
auth.mark_compromised("alice")                             # forces a password change on next login
```

Every function returns `(success, message)`, and the message can be shown to the user.
Users are kept in an in-memory dict (`auth.users`), so they are lost when the program exits.
A real application would store `users[...]["hash"]` in a database.

## What it does

| Requirement | Implementation |
|---|---|
| Length 15–128, no composition rules, no expiry | `MIN_LENGTH`, `MAX_LENGTH` in `auth.py` |
| Unicode handling, no truncation | NFKC normalisation; length counted in code points |
| Blocklist | username and service name, `zxcvbn` (score < 3 is rejected), Have I Been Pwned |
| Strength feedback and reason for rejection | `zxcvbn` feedback returned as the message |
| Salted, slow hashing | Argon2id via `argon2-cffi` (m=64 MiB, t=3, p=4) |
| Pepper | HMAC-SHA256 with `PASSWORD_PEPPER` before hashing |
| Work factor upgrades | rehash on login when parameters change |
| Rate limiting | account locks after 100 consecutive failed logins |

## Troubleshooting

| Problem | Fix |
|---|---|
| `RuntimeError: Set PASSWORD_PEPPER ...` | `.env` is missing, is not in the folder you run from, or the value is shorter than 32 characters. Repeat setup step 3. |
| `ModuleNotFoundError` | The virtual environment is not active, or the dependencies are not installed. Repeat setup steps 1–2. |
| `Could not check the password against breach data` | The Have I Been Pwned API is unreachable. Check your internet connection. |
