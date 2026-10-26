"""Password authentication per NIST SP 800-63B-4 §3.1.1.2 and the OWASP Password Storage Cheat Sheet.

Libraries: argon2-cffi (Argon2id hashing), zxcvbn (strength meter + common-password list),
Have I Been Pwned range API (breached-password blocklist, k-anonymity).
"""
import hashlib
import hmac
import os
import unicodedata

import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from dotenv import load_dotenv
from zxcvbn import zxcvbn

SERVICE_NAME = "htwg-demo"
MIN_LENGTH = 15            # single-factor password (8 would suffice only as part of MFA)
MAX_LENGTH = 128           # SHALL allow at least 64
MAX_FAILED_ATTEMPTS = 100  # §3.2.2: no more than 100 consecutive failures per account

# Argon2id with RFC 9106 low-memory profile (m=64 MiB, t=3, p=4, 16-byte random salt),
# above the OWASP minimum (m=19 MiB, t=2, p=1).
ph = PasswordHasher()
# Secret pepper kept outside the database (env var / .env / secrets manager / HSM).
load_dotenv()  # real environment variables take precedence over .env
PEPPER = os.environ.get("PASSWORD_PEPPER", "").encode()
if len(PEPPER) < 32:
    raise RuntimeError("Set PASSWORD_PEPPER to a random secret of at least 32 bytes")

users: dict[str, dict] = {}  # demo store: username -> {"hash", "failed", "must_change"}
_DUMMY_HASH = ph.hash("dummy")  # equalise timing for unknown usernames


def _normalize(password: str) -> str:
    # NFKC so the same password typed on different devices yields the same bytes;
    # length is then counted in Unicode code points. Nothing is stripped or truncated.
    return unicodedata.normalize("NFKC", password)


def _peppered(password: str) -> str:
    # HMAC-SHA256 with the pepper before Argon2id (OWASP "pre-hashing with a pepper").
    return hmac.new(PEPPER, password.encode(), hashlib.sha256).hexdigest()


def _pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    r = requests.get(f"https://api.pwnedpasswords.com/range/{sha1[:5]}",
                     headers={"Add-Padding": "true"}, timeout=5)
    r.raise_for_status()
    for line in r.text.splitlines():
        suffix, count = line.split(":")
        if suffix == sha1[5:]:
            return int(count)
    return 0


def check_password(password: str, username: str) -> tuple[bool, str]:
    """Return (acceptable, reason/feedback). No composition rules are imposed."""
    password = _normalize(password)
    if len(password) < MIN_LENGTH:
        return False, f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return False, f"Password must be at most {MAX_LENGTH} characters."
    # Blocklist 1: context-specific words (username, service name) and their derivatives.
    if any(w and w.casefold() in password.casefold() for w in (username, SERVICE_NAME, *SERVICE_NAME.split("-"))):
        return False, "Password must not contain your username or the name of this service."
    # Blocklist 2: commonly used / expected passwords and patterns.
    result = zxcvbn(password, user_inputs=[username, SERVICE_NAME])
    if result["score"] < 3:
        fb = result["feedback"]
        return False, " ".join(filter(None, ["Password is too easy to guess.", fb["warning"], *fb["suggestions"]]))
    # Blocklist 3: passwords from known breaches.
    try:
        if _pwned_count(password):
            return False, "This password appeared in a data breach. Choose a different one."
    except requests.RequestException:
        return False, "Could not check the password against breach data. Try again later."
    return True, f"Strength {result['score']}/4"


def register(username: str, password: str) -> tuple[bool, str]:
    if username in users:
        return False, "Username unavailable."
    ok, msg = check_password(password, username)
    if ok:
        users[username] = {"hash": ph.hash(_peppered(_normalize(password))), "failed": 0, "must_change": False}
    return ok, msg


def login(username: str, password: str) -> tuple[bool, str]:
    user = users.get(username)
    if user is None:
        try:
            ph.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        return False, "Invalid username or password."
    if user["failed"] >= MAX_FAILED_ATTEMPTS:
        return False, "Account locked after too many failed attempts. Reset your password."
    peppered = _peppered(_normalize(password))  # whole password is verified, never truncated
    try:
        ph.verify(user["hash"], peppered)
    except (VerificationError, InvalidHashError):
        user["failed"] += 1
        return False, "Invalid username or password."
    user["failed"] = 0
    if ph.check_needs_rehash(user["hash"]):  # transparently upgrade work factors
        user["hash"] = ph.hash(peppered)
    if user["must_change"]:
        return True, "Login ok, but your password must be changed (evidence of compromise)."
    return True, "Login ok."


def change_password(username: str, old: str, new: str) -> tuple[bool, str]:
    # No periodic expiry; changes are user-initiated or forced via mark_compromised().
    ok, msg = login(username, old)
    if not ok:
        return ok, msg
    ok, msg = check_password(new, username)
    if ok:
        users[username].update(hash=ph.hash(_peppered(_normalize(new))), must_change=False)
    return ok, msg


def mark_compromised(username: str) -> None:
    users[username]["must_change"] = True


if __name__ == "__main__":
    for pw in ["password", "Tr0ub4dor&3", "aaaaaaaaaaaaaaaa", "correcthorsebatterystaple",
               "edgar-htwg-demo-123", "kiwi mango rocket violin 42"]:
        print(f"{pw!r:32} ->", check_password(pw, "edgar"))
    print("register:   ", register("edgar", "kiwi mango rocket violin 42"))
    print("login wrong:", login("edgar", "nope"))
    print("login right:", login("edgar", "kiwi mango rocket violin 42"))
    print("login NFKC: ", login("edgar", "ｋｉｗｉ mango rocket violin 42"))  # full-width chars normalise
    print("stored:     ", users["edgar"]["hash"])
